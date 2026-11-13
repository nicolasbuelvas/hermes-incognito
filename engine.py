"""Core privacy engine for Hermes Incognito plugin.

Manages ephemeral session leases, zero-trace file scrubbing, RAM-only PII
vaults, outbound LLM request sanitization, and lifecycle boundary enforcement.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

try:
    from . import pii
except ImportError:
    import pii  # type: ignore[no-redef]

# Allowed Hermes public API imports with fallbacks for standalone/pytest environments
try:
    from hermes_constants import get_hermes_home
except ImportError:
    def get_hermes_home() -> Path:
        env_home = os.environ.get("HERMES_HOME")
        if env_home:
            return Path(env_home).expanduser().resolve()
        return Path.home() / ".hermes"

try:
    from hermes_state import SessionDB
except ImportError:
    SessionDB = None  # type: ignore[assignment,misc]

try:
    from hermes_cli.config import load_config_readonly
except ImportError:
    def load_config_readonly() -> dict[str, Any]:
        return {}

try:
    from plugins.plugin_storage import plugin_data_dir
except ImportError:
    plugin_data_dir = None  # type: ignore[assignment]

try:
    from plugins.plugin_utils import SingletonSlot
except ImportError:
    class SingletonSlot:  # type: ignore[no-redef]
        def __init__(self) -> None:
            self._lock = threading.Lock()
            self._value: Any = None
            self._set = False

        def get(self, factory: Callable[[], Any]) -> Any:
            if self._set:
                return self._value
            with self._lock:
                if self._set:
                    return self._value
                self._value = factory()
                self._set = True
                return self._value

        def peek(self) -> Any:
            return self._value if self._set else None

        def reset(self) -> None:
            with self._lock:
                self._value = None
                self._set = False

try:
    from agent.redact import redact_sensitive_text
except ImportError:
    def redact_sensitive_text(text: str, **kwargs: Any) -> str:
        return text

try:
    from gateway.session_context import get_session_env
except ImportError:
    def get_session_env(name: str = "", default: str = "") -> str:
        return default

try:
    from utils import atomic_json_write, read_json_or_empty
except ImportError:
    def atomic_json_write(path: Path | str, data: Any, **kwargs: Any) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(p)

    def read_json_or_empty(path: Path | str) -> dict[str, Any]:
        p = Path(path)
        if not p.is_file():
            return {}
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

logger = logging.getLogger(__name__)

VALID_MODES: tuple[str, ...] = ("off", "standard", "strict")

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_REQUEST_DUMP = re.compile(r"request_dump_(.+)_[0-9]{8}_[0-9]{6}_[0-9]{6}\.json")


def _valid_session_id(session_id: str) -> bool:
    return isinstance(session_id, str) and _SESSION_ID.fullmatch(session_id) is not None


def _is_incognito_marker(marker: Any) -> bool:
    return isinstance(marker, dict) or marker is True


def _session_files(directory: Path, session_id: str) -> Iterator[Path]:
    names = {f"{session_id}.json", f"{session_id}.jsonl", f"session_{session_id}.json"}
    if directory.is_dir():
        for path in directory.iterdir():
            dump = _REQUEST_DUMP.fullmatch(path.name)
            if path.name in names or (dump and dump[1] == session_id):
                yield path


def _hook_session_dir(directory: Path, session_id: str) -> Path | None:
    root = directory.resolve()
    child = root / session_id
    # Reject aliases even when they point to a different child of the same root.
    try:
        if not child.is_symlink() and child.is_dir() and child.resolve().parts == child.parts:
            return child
    except (OSError, RuntimeError):
        pass
    return None


def _flat_hook_files(directory: Path, session_id: str) -> Iterator[Path]:
    names = {f"{session_id}.txt", f"{session_id}.json", f"{session_id}.jsonl"}
    if directory.is_dir():
        for path in directory.iterdir():
            if path.name in names and (path.is_file() or path.is_symlink()):
                yield path


def _is_pid_alive(pid: int) -> bool:
    """Check whether a PID is alive without using os.kill(pid, 0) on Windows."""
    if pid <= 0:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        pass

    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # The PID exists but belongs to another user; it is still alive.
            return True
        except OSError:
            # Unknown state: never let the sweeper burn a session that may still be live.
            return True
    else:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return True


def _is_ancestor_lease(lease: Any) -> bool:
    """A compacted session whose conversation continues in a newer head session."""
    return isinstance(lease, dict) and bool(lease.get("compacted_into"))


def _live_head_for(leases: dict[str, Any], session_id: str) -> str | None:
    """Return the non-ancestor lease that lists session_id as one of its ancestors."""
    for sid, lease in leases.items():
        if (
            sid != session_id
            and isinstance(lease, dict)
            and not _is_ancestor_lease(lease)
            and session_id in (lease.get("lineage_ids") or [])
        ):
            return sid
    return None


class IncognitoActivationError(RuntimeError):
    """Automatic Incognito activation failed before the first turn."""


class IncognitoEngine:
    """Core runtime engine managing zero-trace incognito state and sanitization."""

    def __init__(self, home_dir: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self._lock_depth = 0
        self.on_burn_complete: Callable[[str], None] | None = None
        self._explicit_home = Path(home_dir).expanduser().resolve() if home_dir else None
        self.config: dict[str, Any] = {}
        # RAM-only masking vaults (placeholder <-> original), one per session. Never persisted.
        self._vaults: dict[str, pii.Vault] = {}
        # Saved chats that can still go back to Incognito: session_id -> undo record (RAM only).
        self._saved: dict[str, dict[str, Any]] = {}

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize ledger transactions across Hermes processes and reentrant engine calls."""
        with self._lock:
            if self._lock_depth:
                yield
                return
            with (self.data_dir / "state.lock").open("a+b") as lock_file:
                if os.name == "nt":
                    import msvcrt
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0
                    # Closing the descriptor releases the OS lock on both platforms.

    @property
    def home_dir(self) -> Path:
        """Resolve the active Hermes home directory."""
        if self._explicit_home is not None:
            return self._explicit_home
        env_home = os.environ.get("HERMES_HOME")
        if env_home:
            return Path(env_home).expanduser().resolve()
        return get_hermes_home()

    @property
    def data_dir(self) -> Path:
        """Resolve plugin data directory without leaking into other namespaces."""
        if self._explicit_home is not None:
            d = self._explicit_home / "plugin-data" / "incognito"
        elif plugin_data_dir is not None:
            try:
                d = plugin_data_dir("incognito")
            except Exception:
                d = self.home_dir / "plugin-data" / "incognito"
        else:
            d = self.home_dir / "plugin-data" / "incognito"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -------------------------------------------------------------------------
    # Internal Ledger Helpers (Thread-safe)
    # -------------------------------------------------------------------------

    def _leases_path(self) -> Path:
        return self.data_dir / "leases.json"

    def _armed_path(self) -> Path:
        return self.data_dir / "armed.json"

    def _audit_path(self) -> Path:
        return self.data_dir / "audit.json"

    def _read_leases(self) -> dict[str, Any]:
        data = read_json_or_empty(self._leases_path())
        return data if isinstance(data, dict) else {}

    def _write_leases(self, leases: dict[str, Any]) -> None:
        atomic_json_write(self._leases_path(), leases)

    def _read_armed(self) -> dict[str, Any] | None:
        data = read_json_or_empty(self._armed_path())
        return data if isinstance(data, dict) and data else None

    def _write_armed(self, armed: dict[str, Any] | None) -> None:
        atomic_json_write(self._armed_path(), armed or {})

    def _read_audit(self) -> dict[str, Any]:
        data = read_json_or_empty(self._audit_path())
        if not isinstance(data, dict) or not data:
            return {
                "sessions_protected": 0,
                "sessions_burned": 0,
                "orphans_swept": 0,
                "writes_blocked": 0,
                "pii_redactions": 0,
                "files_scrubbed": 0,
                "receipts": [],
            }
        data.setdefault("sessions_protected", 0)
        data.setdefault("sessions_burned", 0)
        data.setdefault("orphans_swept", 0)
        data.setdefault("writes_blocked", 0)
        data.setdefault("pii_redactions", 0)
        data.setdefault("files_scrubbed", 0)
        data.setdefault("receipts", [])
        return data

    def _write_audit(self, audit: dict[str, Any]) -> None:
        if "receipts" in audit and isinstance(audit["receipts"], list):
            audit["receipts"] = audit["receipts"][-50:]
        atomic_json_write(self._audit_path(), audit)

    def _record_blocked_write(self, session_id: str) -> None:
        with self._locked():
            leases = self._read_leases()
            if session_id in leases:
                leases[session_id]["blocked_writes"] = leases[session_id].get("blocked_writes", 0) + 1
                self._write_leases(leases)
            audit = self._read_audit()
            audit["writes_blocked"] = audit.get("writes_blocked", 0) + 1
            self._write_audit(audit)

    def _mask_id(self, sid: str) -> str:
        if len(sid) > 10:
            return f"{sid[:4]}…{sid[-4:]}"
        return sid

    # -------------------------------------------------------------------------
    # 1. get_settings
    # -------------------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        """Read plugin configuration settings with safe schema defaults."""
        defaults = {
            "default_mode": "off",
            "auto_purge_on_exit": True,
            "default_ttl_minutes": 60,
            "redact_outbound_pii": False,
            "provider_zdr_hints": True,
            "zero_fill_files": True,
            "save_undo_minutes": 10,
        }
        try:
            cfg = load_config_readonly() or {}
            entries = cfg.get("plugins", {}).get("entries", {})
            plugin_entry = entries.get("incognito", {})
            if not isinstance(plugin_entry, dict):
                plugin_entry = {}
            settings = plugin_entry.get("settings", {})
            if not isinstance(settings, dict):
                settings = {}

            res = dict(defaults)
            for k in defaults:
                if k in settings:
                    res[k] = settings[k]
                elif k in plugin_entry:
                    res[k] = plugin_entry[k]
            if hasattr(self, "config") and isinstance(self.config, dict):
                for k, v in self.config.items():
                    res[k] = v
            return res
        except Exception:
            res = dict(defaults)
            if hasattr(self, "config") and isinstance(self.config, dict):
                for k, v in self.config.items():
                    res[k] = v
            return res

    def set_session_expiry(self, session_id: str, expires_at: float) -> None:
        """Adjust session expiration deadline (used for TTL testing and manual sweeps)."""
        with self._locked():
            leases = self._read_leases()
            if session_id in leases:
                leases[session_id]["expires_at"] = expires_at
                self._write_leases(leases)

    # -------------------------------------------------------------------------
    # 2. arm_next_session
    # -------------------------------------------------------------------------

    def arm_next_session(
        self, mode: str = "standard", ttl_minutes: int | None = None, redact_pii: bool | None = None
    ) -> dict[str, Any]:
        """Arm the next session to automatically start in incognito mode."""
        with self._locked():
            if mode not in ("standard", "strict"):
                raise ValueError(f"Invalid mode '{mode}': must be 'standard' or 'strict'")
            settings = self.get_settings()
            ttl = ttl_minutes if ttl_minutes is not None else settings.get("default_ttl_minutes", 60)
            redact = redact_pii if redact_pii is not None else settings.get("redact_outbound_pii", False)
            armed_state = {
                "mode": mode,
                "ttl_minutes": ttl,
                "redact_pii": redact,
                "armed_at": time.time(),
            }
            self._write_armed(armed_state)
            return {"ok": True, "armed": armed_state}

    # -------------------------------------------------------------------------
    # 3. disarm_next_session
    # -------------------------------------------------------------------------

    def disarm_next_session(self) -> dict[str, Any]:
        """Cancel any armed token for the next session."""
        with self._locked():
            self._write_armed(None)
            return {"ok": True, "armed": None}

    # -------------------------------------------------------------------------
    # 4. get_armed_state
    # -------------------------------------------------------------------------

    def get_armed_state(self) -> dict[str, Any] | None:
        """Inspect pending armed incognito configuration."""
        with self._locked():
            return self._read_armed()

    # -------------------------------------------------------------------------
    # 5. consume_armed_session
    # -------------------------------------------------------------------------

    def consume_armed_session(self, session_id: str) -> dict[str, Any] | None:
        """Activate incognito mode for session_id if armed or default_mode is active."""
        if not _valid_session_id(session_id):
            return None
        with self._locked():
            leases = self._read_leases()
            if session_id in leases:
                return leases[session_id]
            if self._saved_record(session_id) is not None:
                return None

            armed = self._read_armed()
            settings = self.get_settings()
            default_mode = settings.get("default_mode", "off")

            if not armed and default_mode not in ("standard", "strict"):
                return None
            res = self.enable_session(
                session_id=session_id,
                mode=armed["mode"] if armed else default_mode,
                ttl_minutes=armed.get("ttl_minutes") if armed else settings.get("default_ttl_minutes"),
                redact_pii=armed.get("redact_pii") if armed else settings.get("redact_outbound_pii"),
            )
            if not res["ok"]:
                raise IncognitoActivationError(res["error"])
            if armed:
                self._write_armed(None)
            return res["lease"]

    # -------------------------------------------------------------------------
    # 6. enable_session
    # -------------------------------------------------------------------------

    def enable_session(
        self,
        session_id: str,
        mode: str = "standard",
        ttl_minutes: int | None = None,
        redact_pii: bool | None = None,
    ) -> dict[str, Any]:
        """Enable incognito mode for a session, hiding it in SQLite and registering lease.

        An existing lease is updated in place so a mode switch or re-enable keeps its
        lineage, counters, start time, and redaction choice. TTL and redaction change
        only when passed explicitly.
        """
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}
        if mode not in ("standard", "strict"):
            raise ValueError(f"Invalid mode '{mode}': must be 'standard' or 'strict'")

        with self._locked():
            leases = self._read_leases()
            existing = leases.get(session_id)
            if isinstance(existing, dict) and existing.get("pending_burn"):
                return {"ok": False, "error": "Session burn is pending."}
            settings = self.get_settings()
            now = time.time()

            if isinstance(existing, dict):
                lease = dict(existing)
                lease["session_id"] = session_id
                lease["mode"] = mode
                lease["last_activity"] = now
                if redact_pii is not None:
                    lease["redact_pii"] = bool(redact_pii)
                if ttl_minutes is not None:
                    lease["ttl_minutes"] = int(ttl_minutes)
                lineage = lease.get("lineage_ids")
                if not isinstance(lineage, list) or session_id not in lineage:
                    lease["lineage_ids"] = sorted(set((lineage if isinstance(lineage, list) else []) + [session_id]))
                ttl = lease.get("ttl_minutes", 0) or 0
                if not _is_ancestor_lease(lease):
                    lease["expires_at"] = now + (ttl * 60) if ttl > 0 else None
                newly_protected = False
            else:
                ttl = ttl_minutes if ttl_minutes is not None else settings.get("default_ttl_minutes", 60)
                redact = redact_pii if redact_pii is not None else settings.get("redact_outbound_pii", False)
                lease = {
                    "session_id": session_id,
                    "mode": mode,
                    "ttl_minutes": ttl,
                    "owner_pid": os.getpid(),
                    "started_at": now,
                    "last_activity": now,
                    "expires_at": now + (ttl * 60) if ttl > 0 else None,
                    "redact_pii": redact,
                    "blocked_writes": 0,
                    "redactions": 0,
                    "lineage_ids": [session_id],
                }
                newly_protected = True

            if SessionDB is not None and not self._set_history_state({session_id: lease}):
                return {"ok": False, "error": "Could not hide the chat in history. Try again."}

            leases[session_id] = lease
            self._write_leases(leases)
            if newly_protected:
                self._finish_save(session_id)
                audit = self._read_audit()
                audit["sessions_protected"] = audit.get("sessions_protected", 0) + 1
                self._write_audit(audit)

            return {"ok": True, "session_id": session_id, "mode": mode, "lease": lease}

    # -------------------------------------------------------------------------
    # 7. disable_session
    # -------------------------------------------------------------------------

    def disable_session(self, session_id: str, action: str = "keep") -> dict[str, Any]:
        """Disable incognito mode, keeping or immediately burning residual state.

        Keeping a compacted head also releases its ancestor segments, so the retained
        conversation is not swept later as orphaned incognito history.
        """
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}

        if action == "burn":
            return self.burn_session(session_id, reason="disable_burn")

        with self._locked():
            leases = self._read_leases()
            lease = leases.get(session_id)
            if isinstance(lease, dict) and lease.get("pending_burn"):
                return {"ok": False, "error": "Session burn is pending."}
            released = [session_id]
            if isinstance(lease, dict) and not _is_ancestor_lease(lease):
                released += [
                    sid for sid in lease.get("lineage_ids", [])
                    if sid != session_id
                    and _is_ancestor_lease(leases.get(sid))
                    and not leases[sid].get("pending_burn")
                ]
            if SessionDB is not None and not self._set_history_state(dict.fromkeys(released)):
                return {"ok": False, "error": "Could not update chat history. Try again."}

            for sid in released:
                leases.pop(sid, None)
                self._drop_vault(sid)
            self._write_leases(leases)

            return {"ok": True, "session_id": session_id, "mode": "off", "action": "keep"}

    def _set_history_state(self, markers: dict[str, Any]) -> bool:
        """Update visibility and the Incognito marker, restoring previous values on failure."""
        state_db = self.home_dir / "state.db"
        if not state_db.exists():
            return True
        if SessionDB is None:
            return False

        previous = {}
        try:
            db = SessionDB(db_path=state_db)
            try:
                for sid in markers:
                    row = db.get_session(sid)
                    if row is not None:
                        previous[sid] = (
                            bool(row.get("hidden")),
                            db.get_session_model_config_value(sid, "incognito"),
                        )
                try:
                    # Visibility updates can affect the entire compression lineage.
                    for sid in previous:
                        marker = markers[sid]
                        db.patch_session_model_config(sid, {"incognito": marker})
                        if db.get_session_model_config_value(sid, "incognito") != marker:
                            raise RuntimeError("Incognito marker was not updated")
                    for sid in previous:
                        hidden = markers[sid] is not None
                        db.set_session_hidden(sid, hidden)
                        row = db.get_session(sid)
                        if row is None or bool(row.get("hidden")) != hidden:
                            raise RuntimeError("Chat history visibility was not updated")
                except Exception:
                    for sid, (hidden, marker) in previous.items():
                        try:
                            db.set_session_hidden(sid, hidden)
                        except Exception:
                            logger.warning("Could not restore chat history visibility")
                        try:
                            db.patch_session_model_config(sid, {"incognito": marker})
                        except Exception:
                            logger.warning("Could not restore the Incognito history marker")
                    raise
            finally:
                db.close()
        except Exception as exc:
            logger.warning("Could not update Incognito chat history (%s)", type(exc).__name__)
            return False
        return True

    def set_session_ttl(self, session_id: str, ttl_minutes: int) -> dict[str, Any]:
        """Update inactivity TTL in minutes for an active incognito session."""
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}
        with self._locked():
            leases = self._read_leases()
            if session_id not in leases:
                return {"ok": False, "error": f"Session '{session_id}' is not currently incognito"}
            if leases[session_id].get("pending_burn"):
                return {"ok": False, "error": "Session burn is pending."}
            leases[session_id]["ttl_minutes"] = int(ttl_minutes)
            now = time.time()
            if not _is_ancestor_lease(leases[session_id]):
                # Ancestors have no deadline of their own; they burn with their head.
                leases[session_id]["expires_at"] = (
                    now + (int(ttl_minutes) * 60) if int(ttl_minutes) > 0 else None
                )
            self._write_leases(leases)
            return {
                "ok": True,
                "session_id": session_id,
                "ttl_minutes": int(ttl_minutes),
                "expires_at": leases[session_id]["expires_at"],
            }

    # -------------------------------------------------------------------------
    # 8. toggle_session
    # -------------------------------------------------------------------------

    def toggle_session(
        self,
        session_id: str,
        mode: str = "standard",
        ttl_minutes: int | None = None,
        redact_pii: bool | None = None,
    ) -> dict[str, Any]:
        """Toggle incognito mode, disable when mode=='off', or switch mode in place."""
        clean_mode = (mode or "standard").strip().lower()
        if clean_mode == "off":
            return self.disable_session(session_id, action="keep")
        if self.is_incognito(session_id):
            current = self.get_session_state(session_id)
            if current and current.get("mode") != clean_mode and clean_mode in ("standard", "strict"):
                return self.enable_session(
                    session_id, mode=clean_mode, ttl_minutes=ttl_minutes, redact_pii=redact_pii
                )
            return self.disable_session(session_id, action="keep")
        return self.enable_session(
            session_id, mode=clean_mode, ttl_minutes=ttl_minutes, redact_pii=redact_pii
        )

    # -------------------------------------------------------------------------
    # 9. is_incognito
    # -------------------------------------------------------------------------

    def is_incognito(self, session_id: str) -> bool:
        """Check if a session is protected, including while cleanup is pending."""
        if not session_id:
            return False
        with self._locked():
            leases = self._read_leases()
            return session_id in leases

    def get_protected_session_ids(self) -> set[str]:
        """Return all session IDs protected from cross-session search (active or pending burn)."""
        with self._locked():
            protected: set[str] = set()
            leases = self._read_leases()
            for sid, lease in leases.items():
                protected.add(sid)
                if isinstance(lease, dict):
                    for lid in lease.get("lineage_ids", []):
                        if isinstance(lid, str) and lid:
                            protected.add(lid)
            state_db = self.home_dir / "state.db"
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        for sid in db.session_ids_with_model_config_key("incognito"):
                            if isinstance(sid, str) and sid:
                                protected.add(sid)
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception:
                    pass
            return protected

    # -------------------------------------------------------------------------
    # 10. get_session_state
    # -------------------------------------------------------------------------

    def get_session_state(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve current session status, boundaries, and remaining TTL."""
        if not session_id or not self.is_incognito(session_id):
            return None

        with self._locked():
            leases = self._read_leases()
            lease = leases.get(session_id)
            if not lease:
                return None

            expires_at = lease.get("expires_at")
            remaining = max(0, int(expires_at - time.time())) if expires_at else None

            return {
                "active": True,
                "pending_burn": bool(lease.get("pending_burn")),
                "session_id": session_id,
                "mode": lease.get("mode", "standard"),
                "hidden": True,
                "ttl_minutes": lease.get("ttl_minutes", 0),
                "auto_purge_on_exit": self.get_settings()["auto_purge_on_exit"],
                "expires_at": expires_at,
                "remaining_seconds": remaining,
                "blocked_writes": lease.get("blocked_writes", 0),
                "redactions": lease.get("redactions", 0),
                "redact_pii": lease.get("redact_pii", False),
                "started_at": lease.get("started_at"),
                "masked_counts": self._vaults[session_id].counts() if session_id in self._vaults else {},
            }

    # -------------------------------------------------------------------------
    # 11. touch_session
    # -------------------------------------------------------------------------

    def ensure_hidden_in_db(self, session_id: str) -> None:
        """Ensure an active incognito session stays hidden in SessionDB after turn writes."""
        if not session_id:
            return
        with self._locked():
            leases = self._read_leases()
            lease = leases.get(session_id)
            if not lease:
                return
            state_db = self.home_dir / "state.db"
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        db.set_session_hidden(session_id, True)
                        db.patch_session_model_config(session_id, {"incognito": lease})
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception:
                    pass

    def touch_session(self, session_id: str) -> None:
        """Refresh session activity timestamp and extend expiration deadline."""
        if not session_id:
            return
        with self._locked():
            leases = self._read_leases()
            lease = leases.get(session_id)
            if isinstance(lease, dict) and not lease.get("pending_burn") and not _is_ancestor_lease(lease):
                now = time.time()
                leases[session_id]["last_activity"] = now
                if not leases[session_id].get("owner_pid"):
                    leases[session_id]["owner_pid"] = os.getpid()
                ttl = leases[session_id].get("ttl_minutes", 0)
                if ttl > 0:
                    leases[session_id]["expires_at"] = now + (ttl * 60)
                self._write_leases(leases)

    def live_head_for(self, session_id: str) -> str | None:
        """Return the live session that continues a compacted ancestor, if any."""
        with self._locked():
            leases = self._read_leases()
            if not _is_ancestor_lease(leases.get(session_id)):
                return None
            return _live_head_for(leases, session_id)

    # -------------------------------------------------------------------------
    # 12. propagate_compaction
    # -------------------------------------------------------------------------

    def propagate_compaction(self, old_session_id: str, new_session_id: str) -> dict[str, Any]:
        """Propagate incognito lease and vault state across session compaction chains."""
        if not old_session_id or not new_session_id:
            return {"ok": False, "error": "both old and new session IDs are required"}
        if not (_valid_session_id(old_session_id) and _valid_session_id(new_session_id)):
            return {"ok": False, "error": "Invalid session ID."}
        if old_session_id == new_session_id:
            return {"ok": False, "error": "Compaction requires a new session ID."}

        with self._locked():
            leases = self._read_leases()
            old_lease = leases.get(old_session_id)
            if not old_lease:
                if self.propagate_saved_compaction(old_session_id, new_session_id):
                    return {"ok": True, "propagated": False, "saved": True, "session_id": new_session_id}
                return {"ok": True, "propagated": False, "session_id": new_session_id}

            root_id = _live_head_for(leases, old_session_id) if _is_ancestor_lease(old_lease) else None
            now = time.time()
            ancestor_lineage = sorted(set(list(old_lease.get("lineage_ids") or []) + [old_session_id]))

            # The new session is the live head: it carries the whole ancestor chain and its own TTL.
            new_lease = dict(old_lease)
            new_lease.pop("compacted_into", None)
            new_lease["session_id"] = new_session_id
            new_lease["lineage_ids"] = sorted(set(ancestor_lineage + [new_session_id]))
            new_lease["last_activity"] = now
            ttl = new_lease.get("ttl_minutes", 0) or 0
            new_lease["expires_at"] = now + (ttl * 60) if ttl > 0 else None

            # The old session becomes an ancestor. It has no TTL of its own and lists only
            # its own ancestors, so burning it can never cascade into the live head.
            old_lease = dict(old_lease)
            old_lease["compacted_into"] = new_session_id
            old_lease["expires_at"] = None
            old_lease["lineage_ids"] = ancestor_lineage

            # The new head continues the same conversation: share its masking vault so a value
            # keeps its placeholder across the compaction.
            if old_session_id in self._vaults:
                self._vaults[new_session_id] = self._vaults[old_session_id]

            leases[new_session_id] = new_lease
            leases[old_session_id] = old_lease
            if root_id:
                new_lease["compacted_into"] = root_id
                new_lease["expires_at"] = None
                self._add_subagent_lease(leases, root_id, new_lease)
            self._write_leases(leases)

            # Update SessionDB
            state_db = self.home_dir / "state.db"
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        db.set_session_hidden(new_session_id, True)
                        db.patch_session_model_config(new_session_id, {"incognito": new_lease})
                        if db.get_session_model_config_value(old_session_id, "incognito") is not None:
                            db.patch_session_model_config(old_session_id, {"incognito": old_lease})
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception:
                    pass

            return {
                "ok": True,
                "propagated": True,
                "old_session_id": old_session_id,
                "new_session_id": new_session_id,
                "mode": new_lease.get("mode", "standard"),
            }

    # -------------------------------------------------------------------------
    # 13. burn_session
    # -------------------------------------------------------------------------

    def _count_db_rows_for_ids(self, state_db: Path, target_ids: set[str]) -> int | None:
        """Count remaining rows across sessions and messages tables for target_ids."""
        if not state_db.exists() or not target_ids:
            return 0
        try:
            conn = sqlite3.connect(f"{state_db.as_uri()}?mode=ro", uri=True)
            try:
                return sum(
                    conn.execute(f"SELECT count(*) FROM {table} WHERE {column} = ?", (sid,)).fetchone()[0]
                    for sid in target_ids
                    for table, column in (("sessions", "id"), ("messages", "session_id"))
                )
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.debug("Cannot verify incognito database cleanup: %s", exc)
            return None

    def _schedule_deferred_burn(self, session_id: str, attempt: int = 1) -> None:
        """Retry burning a busy session once its active Gateway turn admission settles."""
        delays = {1: 1.5, 2: 5.0, 3: 15.0}
        delay = delays.get(attempt)
        if delay is None:
            return

        def _retry() -> None:
            try:
                with self._locked():
                    leases = self._read_leases()
                    lease = leases.get(session_id)
                    if not lease or not lease.get("pending_burn"):
                        return
                res = self.burn_session(session_id, reason="deferred_burn_retry", _retry_attempt=attempt)
                if res.get("pending_burn"):
                    self._schedule_deferred_burn(session_id, attempt=attempt + 1)
            except Exception as exc:
                logger.debug("Deferred burn retry failed for %s: %s", session_id, exc)

        timer = threading.Timer(delay, _retry)
        timer.daemon = True
        timer.start()

    def _scrub_burn_files(self, target_ids: set[str]) -> tuple[int, bool]:
        """Scrub authorized artifacts and report whether any cleanup must be retried."""
        zero_fill = self.get_settings().get("zero_fill_files", True)
        files_scrubbed = 0
        files_pending = False

        def _failed(exc: OSError | RuntimeError) -> None:
            nonlocal files_pending
            if not isinstance(exc, FileNotFoundError):
                files_pending = True
                logger.debug("Incognito file cleanup deferred: %s", exc)

        def _scrub_file(file_path: Path) -> None:
            nonlocal files_scrubbed, files_pending
            try:
                if file_path.resolve().parts != file_path.parts:
                    files_pending = True
                    return
                info = file_path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    files_pending = True
                    return
                if zero_fill and info.st_nlink == 1 and info.st_size > 0:
                    with file_path.open("r+b") as handle:
                        opened = os.fstat(handle.fileno())
                        if not os.path.samestat(info, opened) or opened.st_nlink != 1:
                            files_pending = True
                            return
                        handle.write(b"\x00" * opened.st_size)
                        handle.flush()
                        os.fsync(handle.fileno())
                file_path.unlink()
                files_scrubbed += 1
            except (OSError, RuntimeError) as exc:
                _failed(exc)

        try:
            sessions_dir = (self.home_dir / "sessions").resolve()
            hook_outputs_dir = (self.home_dir / "hook_outputs").resolve()
            for sid in target_ids:
                for path in _session_files(sessions_dir, sid):
                    _scrub_file(path)
                for path in _flat_hook_files(hook_outputs_dir, sid):
                    _scrub_file(path)

                sid_dir = _hook_session_dir(hook_outputs_dir, sid)
                if sid_dir is None:
                    # A missing directory is clean. An unsafe or unreadable entry is not.
                    try:
                        (hook_outputs_dir / sid).lstat()
                    except OSError as exc:
                        _failed(exc)
                    else:
                        files_pending = True
                    continue

                for directory, _, files in os.walk(sid_dir, topdown=False, onerror=_failed, followlinks=False):
                    current_dir = Path(directory)
                    if current_dir.resolve().parts != current_dir.parts:
                        files_pending = True
                        continue
                    for name in files:
                        _scrub_file(current_dir / name)
                    try:
                        current_dir.rmdir()
                    except OSError as exc:
                        _failed(exc)
        except (OSError, RuntimeError) as exc:
            _failed(exc)
        return files_scrubbed, files_pending

    def burn_session(
        self, session_id: str, reason: str = "burn", *, _retry_attempt: int = 0
    ) -> dict[str, Any]:
        """Perform zero-trace scrub of SQLite rows, transcript files, and RAM vault."""
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}

        with self._locked():
            leases = self._read_leases()
            lease = leases.get(session_id, {})
            authorized_leases: dict[str, dict[str, Any]] = {}
            state_db = self.home_dir / "state.db"
            db = None
            try:
                if SessionDB is not None and state_db.exists():
                    db = SessionDB(db_path=state_db)
            except Exception as exc:
                logger.debug("Cannot open SessionDB for incognito burn: %s", exc)

            def _authorized(sid: str) -> bool:
                if isinstance(leases.get(sid), dict):
                    authorized_leases[sid] = leases[sid]
                    return True
                if db is not None:
                    try:
                        marker = db.get_session_model_config_value(sid, "incognito")
                        if _is_incognito_marker(marker):
                            authorized_leases[sid] = marker if isinstance(marker, dict) else {}
                            return True
                    except Exception as exc:
                        logger.debug("Cannot check incognito marker for %s: %s", sid, exc)
                return False

            try:
                if not _authorized(session_id):
                    return {"ok": False, "error": "Burn requires an incognito session."}

                def _may_cascade(sid: str) -> bool:
                    """Cascade only to ancestors; never to a live descendant or another live session."""
                    member = leases.get(sid)
                    if not isinstance(member, dict) or member.get("pending_burn"):
                        return True
                    if session_id in (member.get("lineage_ids") or []):
                        return False  # sid continues this session: it is a descendant
                    return _is_ancestor_lease(member)

                target_ids = {session_id}
                if isinstance(lease, dict):
                    target_ids.update(
                        sid for sid in lease.get("lineage_ids", [])
                        if _valid_session_id(sid) and _may_cascade(sid) and _authorized(sid)
                    )

                # Live sessions outside this burn must survive even if Hermes would cascade into them.
                live_outside = {
                    sid for sid, other in leases.items()
                    if sid not in target_ids and isinstance(other, dict) and not other.get("pending_burn")
                }

                def _authorized_cascade_target(target: str, owner_sid: str) -> bool:
                    if _authorized(target):
                        return True
                    if db is not None and hasattr(db, "get_session"):
                        try:
                            row = db.get_session(target)
                            if (
                                isinstance(row, dict)
                                and row.get("source") == "delegate"
                                and row.get("parent_session_id") in authorized_leases
                            ):
                                authorized_leases[target] = dict(authorized_leases.get(owner_sid, {}))
                                return True
                        except Exception as exc:
                            logger.debug("Cannot inspect delegate child %s: %s", target, exc)
                    return False

                delete_plan: dict[str, list[str]] = {}
                if db is not None:
                    for sid in sorted(target_ids):
                        try:
                            delete_ids = db.get_session_delete_targets(sid)
                            if delete_ids and all(
                                _valid_session_id(target)
                                and target not in live_outside
                                and _authorized_cascade_target(target, sid)
                                for target in delete_ids
                            ):
                                delete_plan[sid] = delete_ids
                                target_ids.update(delete_ids)
                        except Exception as exc:
                            logger.debug("Cannot plan SessionDB deletion for %s: %s", sid, exc)

                # Persist recovery before deleting a row that may hold the only incognito marker.
                lineage = sorted(target_ids)
                for sid in lineage:
                    leases[sid] = {
                        **authorized_leases[sid],
                        "session_id": sid,
                        "pending_burn": True,
                        "expires_at": 0,
                        "lineage_ids": lineage,
                    }
                self._write_leases(leases)

                rows_before = self._count_db_rows_for_ids(state_db, target_ids)
                db_deleted = False
                if db is not None:
                    for sid, delete_ids in delete_plan.items():
                        try:
                            # Fence the authorized cascade inside the API's write transaction.
                            if db.delete_session(
                                sid, expected_delete_ids=delete_ids, exclude_active_write_guards=True
                            ):
                                db_deleted = True
                        except Exception as exc:
                            logger.debug("SessionDB.delete_session deferred for %s: %s", sid, exc)
            finally:
                if db is not None:
                    db.close()

            rows_after = self._count_db_rows_for_ids(state_db, target_ids)
            db_deleted = rows_after == 0 and (
                db_deleted or bool(rows_before) or bool(authorized_leases[session_id].get("db_deleted"))
            )
            files_scrubbed, files_pending = self._scrub_burn_files(target_ids)
            pending_burn = rows_after != 0 or files_pending

            vault_keys_cleared = 0
            if pending_burn:
                for sid in target_ids:
                    leases[sid]["db_deleted"] = db_deleted
            else:
                for sid in target_ids:
                    leases.pop(sid, None)
                    self._saved.pop(sid, None)
                    vault_keys_cleared += self._drop_vault(sid)
            self._write_leases(leases)

            if pending_burn and _retry_attempt == 0:
                self._schedule_deferred_burn(session_id, attempt=1)

            # 5. Record content-free receipt in audit.json
            now_ts = time.time()
            session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
            receipt_id = session_hash[:16]
            receipt = {
                "receipt_id": receipt_id,
                "session_hash": session_hash,
                "timestamp": now_ts,
                "reason": reason,
                "db_deleted": db_deleted,
                "pending_burn": pending_burn,
                "files_pending": files_pending,
                "files_scrubbed": files_scrubbed,
                "vault_keys_cleared": vault_keys_cleared,
            }

            audit = self._read_audit()
            if not pending_burn:
                audit["sessions_burned"] = audit.get("sessions_burned", 0) + 1
            audit["files_scrubbed"] = audit.get("files_scrubbed", 0) + files_scrubbed
            if _retry_attempt == 0 or not pending_burn:
                audit.setdefault("receipts", []).append(receipt)
            self._write_audit(audit)

            if not pending_burn and self.on_burn_complete is not None:
                for sid in sorted(target_ids):
                    try:
                        self.on_burn_complete(sid)
                    except Exception:
                        logger.debug("Could not notify Desktop about completed Incognito cleanup")

            return {
                "ok": True,
                "session_id": session_id,
                "reason": reason,
                "db_deleted": db_deleted,
                "pending_burn": pending_burn,
                "files_pending": files_pending,
                "files_scrubbed": files_scrubbed,
                "vault_keys_cleared": vault_keys_cleared,
                "receipt_id": receipt_id,
                "timestamp": now_ts,
            }

    # -------------------------------------------------------------------------
    # 14. sweep_expired
    # -------------------------------------------------------------------------

    def sweep_expired(self, force_dead_pids: bool = True) -> dict[str, Any]:
        """Sweep expired TTL leases and orphaned sessions from dead processes."""
        with self._locked():
            now = time.time()
            leases = self._read_leases()
            to_burn: dict[str, str] = {}

            for sid, lease in leases.items():
                if isinstance(lease, dict) and lease.get("pending_burn"):
                    to_burn[sid] = "pending_burn_retry"
                    continue
                if _is_ancestor_lease(lease):
                    # Ancestors burn with their live head, never on their own TTL or owner PID.
                    if _live_head_for(leases, sid) is None:
                        to_burn[sid] = "orphaned_ancestor"
                    continue
                expires_at = lease.get("expires_at")
                owner_pid = lease.get("owner_pid")
                if expires_at and now >= expires_at:
                    to_burn[sid] = "expired_ttl"
                elif force_dead_pids and owner_pid and owner_pid != os.getpid() and not _is_pid_alive(owner_pid):
                    to_burn[sid] = "dead_owner_pid"

            # Check DB for model_config incognito orphans
            state_db = self.home_dir / "state.db"
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        db_incognito_ids = db.session_ids_with_model_config_key("incognito")
                        saved_members = {
                            sid for record in self._read_saved().values() if isinstance(record, dict)
                            for sid in (record.get("leases") or {})
                        }
                        for sid in db_incognito_ids:
                            if sid not in leases and sid not in to_burn and sid not in saved_members:
                                row = db.get_session(sid) if hasattr(db, "get_session") else None
                                should_burn_orphan = True
                                if isinstance(row, dict) and not row.get("ended_at"):
                                    try:
                                        mc = json.loads(row.get("model_config") or "{}")
                                        inc = mc.get("incognito") if isinstance(mc, dict) else None
                                        if isinstance(inc, dict) and not inc.get("pending_burn"):
                                            exp = inc.get("expires_at")
                                            pid = inc.get("owner_pid")
                                            expired = bool(exp and now >= exp)
                                            dead = bool(force_dead_pids and pid and pid != os.getpid() and not _is_pid_alive(pid))
                                            if not expired and not dead:
                                                # Re-adopt live incognito session into leases instead of burning mid-chat
                                                leases[sid] = inc
                                                self._write_leases(leases)
                                                should_burn_orphan = False
                                    except Exception:
                                        pass
                                if should_burn_orphan:
                                    to_burn[sid] = "orphaned_db_session"
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception:
                    pass

            swept_receipts = []
            for sid, reason in to_burn.items():
                if sid in leases and sid not in self._read_leases():
                    continue  # already burned as an ancestor of an earlier target
                res = self.burn_session(sid, reason=reason)
                if res.get("ok") and not res.get("pending_burn"):
                    swept_receipts.append(res)

            if swept_receipts:
                audit = self._read_audit()
                audit["orphans_swept"] = audit.get("orphans_swept", 0) + len(swept_receipts)
                self._write_audit(audit)

            remaining_leases = {
                k: v for k, v in self._read_leases().items() if not (isinstance(v, dict) and v.get("pending_burn"))
            }
            return {
                "ok": True,
                "swept_count": len(swept_receipts),
                "swept_receipts": swept_receipts,
                "active_remaining": len(remaining_leases),
            }

    # -------------------------------------------------------------------------
    # 15. verify_zero_trace
    # -------------------------------------------------------------------------

    def verify_zero_trace(self, session_id: str) -> dict[str, Any]:
        """Verify zero residual trace across SQLite rows, disk files, and RAM vault."""
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}

        with self._locked():
            db_rows_found = self._count_db_rows_for_ids(self.home_dir / "state.db", {session_id})

            sessions_dir = self.home_dir / "sessions"
            session_files_found = sum(
                path.is_file() or path.is_symlink() for path in _session_files(sessions_dir, session_id)
            )

            hook_outputs_dir = self.home_dir / "hook_outputs"
            hook_files_found = sum(1 for _ in _flat_hook_files(hook_outputs_dir, session_id))
            sid_dir = _hook_session_dir(hook_outputs_dir, session_id)
            if sid_dir is not None:
                hook_files_found += sum(1 for _ in sid_dir.glob("**/*"))
            elif (hook_outputs_dir / session_id).is_symlink():
                hook_files_found += 1

            ram_vault_entries = len(self._vaults.get(session_id, {}))
            leases = self._read_leases()
            active_lease = session_id in leases

            session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
            audit = self._read_audit()
            burn_receipt = None
            for rec in reversed(audit.get("receipts", [])):
                if rec.get("session_hash") == session_hash:
                    burn_receipt = rec
                    break

            zero_trace = (
                db_rows_found == 0
                and session_files_found == 0
                and hook_files_found == 0
                and ram_vault_entries == 0
                and not active_lease
            )

            return {
                "ok": True,
                "session_id": session_id,
                "zero_trace": zero_trace,
                "db_rows_found": db_rows_found,
                "session_files_found": session_files_found,
                "hook_files_found": hook_files_found,
                "ram_vault_entries": ram_vault_entries,
                "active_lease": active_lease,
                "receipt_id": burn_receipt.get("receipt_id") if burn_receipt else None,
                "burn_receipt": burn_receipt,
            }

    # -------------------------------------------------------------------------
    # 16. status_summary
    # -------------------------------------------------------------------------

    def status_summary(self, session_id: str = "", *, include_global: bool = True) -> dict[str, Any]:
        """Aggregate status, armed state, active sessions, and audit metrics.

        Operator surfaces (CLI, Desktop, RPC, REST) get the full host view. The model-facing
        tool passes include_global=False and sees only its own session.
        """
        if not include_global:
            return self._session_status(session_id)
        with self._locked():
            current_state = self.get_session_state(session_id) if session_id else None
            armed = self.get_armed_state()
            leases = self._read_leases()
            active_leases = {
                k: v for k, v in leases.items() if not (isinstance(v, dict) and v.get("pending_burn"))
            }
            audit = self._read_audit()
            settings = self.get_settings()

            is_active = bool(current_state and current_state.get("active"))
            current_mode = current_state.get("mode", "off") if current_state else "off"
            current_redact = current_state.get("redact_pii", False) if current_state else settings.get("redact_outbound_pii", False)

            return {
                "ok": True,
                "incognito": is_active,
                "mode": current_mode,
                "session_state": current_state,
                "current_session": current_state,
                "armed": armed,
                "saved": self.saved_state(session_id) if session_id else None,
                "active_count": len(active_leases),
                "active_sessions": [self._mask_id(sid) for sid in active_leases.keys()],
                "audit": audit,
                "metrics": {
                    "sessions_protected": audit.get("sessions_protected", 0),
                    "sessions_burned": audit.get("sessions_burned", 0),
                    "orphans_swept": audit.get("orphans_swept", 0),
                    "blocked_writes": current_state.get("blocked_writes", 0) if current_state else audit.get("writes_blocked", 0),
                    "ram_redactions": current_state.get("redactions", 0) if current_state else audit.get("pii_redactions", 0),
                    "pii_tokens_masked": audit.get("pii_redactions", 0),
                    "files_zero_filled": audit.get("files_scrubbed", 0),
                },
                "settings": settings,
                "boundaries": {
                    "memory_blocks": True,
                    "skill_blocks": True,
                    "profile_memory_stripped": current_mode == "strict",
                    "search_blocked": current_mode == "strict",
                    "outbound_pii_redacted": current_redact,
                    "zero_fill_on_burn": settings.get("zero_fill_files", True),
                },
            }

    def _session_status(self, session_id: str) -> dict[str, Any]:
        """Status for a single session without other sessions or host-wide audit data."""
        with self._locked():
            current_state = self.get_session_state(session_id) if _valid_session_id(session_id) else None
            settings = self.get_settings()
            is_active = bool(current_state and current_state.get("active"))
            current_mode = current_state.get("mode", "off") if current_state else "off"
            current_redact = (
                current_state.get("redact_pii", False) if current_state
                else settings.get("redact_outbound_pii", False)
            )
            return {
                "ok": True,
                "incognito": is_active,
                "mode": current_mode,
                "session_state": current_state,
                "current_session": current_state,
                "armed": self.get_armed_state(),
                "saved": self.saved_state(session_id) if session_id else None,
                "metrics": {
                    "blocked_writes": current_state.get("blocked_writes", 0) if current_state else 0,
                    "ram_redactions": current_state.get("redactions", 0) if current_state else 0,
                },
                "boundaries": {
                    "memory_blocks": True,
                    "skill_blocks": True,
                    "profile_memory_stripped": current_mode == "strict",
                    "search_blocked": current_mode == "strict",
                    "outbound_pii_redacted": current_redact,
                    "zero_fill_on_burn": settings.get("zero_fill_files", True),
                },
            }

    # -------------------------------------------------------------------------
    # 17. evaluate_tool_guard & scrub_tool_result
    # -------------------------------------------------------------------------

    def evaluate_tool_guard(
        self, session_id: str, tool_name: str, args: dict[str, Any] | None = None
    ) -> dict[str, str] | None:
        """Enforce tool execution boundaries for incognito sessions and cross-session reads."""
        with self._locked():
            calls_to_check: list[tuple[str, dict[str, Any]]] = []
            if tool_name == "tool_call" and isinstance(args, dict) and isinstance(args.get("calls"), list):
                for entry in args["calls"]:
                    if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                        entry_args = entry.get("arguments")
                        calls_to_check.append((entry["name"], entry_args if isinstance(entry_args, dict) else {}))
            else:
                calls_to_check.append((tool_name, args if isinstance(args, dict) else {}))

            protected_ids = self.get_protected_session_ids()
            norm_home = str(self.home_dir).replace("\\", "/").lower()
            is_caller_incog = bool(session_id and self.is_incognito(session_id))
            caller_mode = "off"
            if is_caller_incog:
                leases = self._read_leases()
                caller_mode = leases.get(session_id, {}).get("mode", "standard")

            for t_name, t_args in calls_to_check:
                if t_name == "incognito_control":
                    # Deletion is reserved for user-facing controls. Refuse model-started burns and
                    # sweeps before the tool runs, including when wrapped in a deferred tool_call.
                    incog_action = str(t_args.get("action") or "status").strip().lower()
                    incog_disable = str(
                        t_args.get("disable_action") or ("keep" if t_args.get("keep", True) else "burn")
                    ).strip().lower()
                    if incog_action in ("burn", "sweep") or (
                        incog_action in ("disable", "off") and incog_disable == "burn"
                    ):
                        return {
                            "action": "block",
                            "message": (
                                "The model cannot delete sessions. Ask the user to run /incognito burn "
                                "or use the Desktop Burn control."
                            ),
                        }

                if t_name == "session_search":
                    target_sid = t_args.get("session_id")
                    if isinstance(target_sid, str) and target_sid in protected_ids:
                        return {
                            "action": "block",
                            "message": "Target session is protected by incognito mode and cannot be read.",
                        }

                # Prevent raw SQLite / filesystem bypasses (execute_code, terminal, read_file, search_files)
                # against state.db / sessions/ whenever any incognito session is active on the host,
                # or against memories/ when the caller itself is in strict clean-room mode.
                if (protected_ids or caller_mode == "strict") and t_name in (
                    "execute_code",
                    "terminal",
                    "read_file",
                    "search_files",
                ):
                    payload_blob = json.dumps(t_args, ensure_ascii=False).replace("\\\\", "/").replace("\\", "/").lower()
                    session_store_markers = (
                        f"{norm_home}/state.db",
                        f"{norm_home}/sessions",
                        f"{norm_home}/hook_outputs",
                        "hermes/state.db",
                        "/state.db",
                    )
                    if protected_ids and any(m in payload_blob for m in session_store_markers):
                        if is_caller_incog:
                            self._record_blocked_write(session_id)
                        return {
                            "action": "block",
                            "message": (
                                f"Direct access to Hermes session storage via '{t_name}' is blocked while "
                                "incognito sessions are active. Use 'session_search' instead."
                            ),
                        }
                    if caller_mode == "strict":
                        strict_markers = (
                            *session_store_markers,
                            f"{norm_home}/memories",
                            "/memories/user.md",
                            "/memories/memory.md",
                        )
                        if any(m in payload_blob for m in strict_markers):
                            self._record_blocked_write(session_id)
                            return {
                                "action": "block",
                                "message": f"Reading persistent Hermes memory/session storage via '{t_name}' is blocked in strict incognito mode.",
                            }

            if not is_caller_incog:
                if session_id and self._saved_record(session_id) is not None:
                    for t_name, _t_args in calls_to_check:
                        if t_name in ("memory", "skill_manage"):
                            return {
                                "action": "block",
                                "message": (
                                    f"Tool '{t_name}' is blocked while this chat can still go back to "
                                    "Incognito (Undo is available)."
                                ),
                            }
                return None

            mode = caller_mode

            for t_name, _t_args in calls_to_check:
                # Standard mode blocks persistent mutations
                if t_name in ("memory", "skill_manage"):
                    self._record_blocked_write(session_id)
                    return {
                        "action": "block",
                        "message": f"Tool '{t_name}' is blocked in incognito session to prevent persistent state mutations.",
                    }

                # Strict mode also blocks history exploration and background cron
                if mode == "strict":
                    if t_name in ("session_search", "cronjob_manage"):
                        self._record_blocked_write(session_id)
                        return {
                            "action": "block",
                            "message": f"Tool '{t_name}' is blocked in strict incognito mode.",
                        }
                    if t_name == "send_message":
                        return {
                            "action": "approve",
                            "message": "External messaging via 'send_message' requires user confirmation in strict incognito mode.",
                        }

            return None

    def scrub_tool_result(
        self,
        session_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        result: Any = None,
    ) -> str | None:
        """Filter incognito sessions out of cross-session search and tool outputs."""
        if not isinstance(result, str) or not result:
            return None
        if tool_name not in ("session_search", "tool_call", "execute_code", "terminal", "read_file", "search_files"):
            return None

        protected_ids = self.get_protected_session_ids()
        if not protected_ids:
            return None

        # Quick substring check before parsing
        if not any(pid in result for pid in protected_ids):
            return None

        if tool_name not in ("session_search", "tool_call"):
            # Scrub lines referencing protected session IDs in raw execution/file outputs
            scrubbed_lines = [
                "[REDACTED INCOGNITO SESSION]" if any(pid in line for pid in protected_ids) else line
                for line in result.splitlines(keepends=True)
            ]
            return "".join(scrubbed_lines)

        try:
            data = json.loads(result)
        except Exception:
            return None

        modified = False

        def _scrub_payload(node: Any) -> Any:
            nonlocal modified
            if isinstance(node, dict):
                sid = node.get("session_id")
                if isinstance(sid, str) and sid in protected_ids:
                    modified = True
                    return {"success": False, "error": "Session is protected by incognito mode."}
                cleaned: dict[str, Any] = {}
                for k, v in node.items():
                    if k in ("results", "sessions", "matches") and isinstance(v, list):
                        filtered = [
                            item
                            for item in v
                            if not (isinstance(item, dict) and item.get("session_id") in protected_ids)
                        ]
                        if len(filtered) != len(v):
                            modified = True
                            cleaned[k] = [_scrub_payload(item) for item in filtered]
                            continue
                    cleaned[k] = _scrub_payload(v)
                if modified and "results" in cleaned and isinstance(cleaned["results"], list):
                    if "count" in cleaned and isinstance(cleaned["count"], int):
                        cleaned["count"] = len(cleaned["results"])
                    if "total" in cleaned and isinstance(cleaned["total"], int):
                        cleaned["total"] = len(cleaned["results"])
                return cleaned
            elif isinstance(node, list):
                filtered_list = [
                    _scrub_payload(item)
                    for item in node
                    if not (isinstance(item, dict) and item.get("session_id") in protected_ids)
                ]
                if len(filtered_list) != len(node):
                    modified = True
                return filtered_list
            return node

        scrubbed = _scrub_payload(data)
        if not modified:
            return None
        return json.dumps(scrubbed, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # 17b. transform_llm_request
    # -------------------------------------------------------------------------

    @staticmethod
    def _strip_memory_blocks(text: str) -> str:
        """Strip Hermes MEMORY and USER PROFILE blocks across both double-bar and single-bar layouts."""
        if not text:
            return text
        # 1. Standard Hermes double-bar layout:
        #    ══════\nMEMORY (your personal notes) [99% — ...]\n══════\n<entries>
        #    Ends before the next ══════ block, plugin section, profile/timestamp/runtime trailer, or EOF.
        double_bar = re.compile(
            r"(?is)[═=\-_]{5,}\s*\n\s*(?:MEMORY|USER PROFILE)\s*\([^)]*\)[^\n]*\n[═=\-_]{5,}\s*\n.*?"
            r"(?=\n\n(?:[═=\-_]{5,}|<!--\s*hermes-plugin-sections:start\s*-->|##\s+Plugin Context:|"
            r"Active Hermes profile:|Conversation started:|#\s+Hermes runtime environment)|\n[═=\-_]{5,}\s*\n|\Z)"
        )
        res = double_bar.sub("", text)

        # 2. Single-bar or markdown heading layout (e.g. unit tests / compact prompts):
        #    ══════\nMEMORY (your personal notes)\n<entries>\n══════
        single_bar = re.compile(
            r"(?is)(?:[═=\-_]{5,}\s*\n)?\s*(?:MEMORY|USER PROFILE)\s*\([^)]*\)[^\n]*\n.*?"
            r"(?=(?:[═=\-_]{5,}\s*\n)|\n\n(?:<!--\s*hermes-plugin-sections:start\s*-->|##\s+Plugin Context:|"
            r"Active Hermes profile:|Conversation started:|#\s+Hermes runtime environment)|\Z)"
        )
        if re.search(r"(?i)(?:MEMORY|USER PROFILE)\s*\([^)]*\)", res):
            marker = "\x00incognito-stripped\x00"
            res = single_bar.sub(marker, res)
            # Drop only the closing separator of a removed block, never unrelated rules elsewhere.
            res = re.sub(re.escape(marker) + r"(?:[ \t]*[═=\-_]{5,}[ \t]*(?:\n|\Z))?", "", res)

        # Collapse excess blank lines left behind by removed blocks
        res = re.sub(r"\n{3,}", "\n\n", res)
        return res.strip()

    # -------------------------------------------------------------------------
    # 18. Personal-detail masking (fail-closed)
    # -------------------------------------------------------------------------

    def masking_active(self, session_id: str) -> bool:
        """True when this session's outbound content must be masked."""
        if not session_id:
            return False
        with self._locked():
            lease = self._read_leases().get(session_id)
            if isinstance(lease, dict):
                redact = lease.get("redact_pii")
                if redact is None:
                    redact = self.get_settings().get("redact_outbound_pii", False)
                return bool(redact)
            saved = self._saved_record(session_id)
            return bool(saved and saved.get("redact_pii"))

    def _vault_for(self, session_id: str) -> pii.Vault:
        vault = self._vaults.get(session_id)
        if vault is None:
            vault = self._vaults[session_id] = pii.Vault()
        return vault

    def _drop_vault(self, session_id: str) -> int:
        vault = self._vaults.pop(session_id, None)
        if vault is None or any(v is vault for v in self._vaults.values()):
            return 0
        return vault.clear()

    def store_vault_entry(self, session_id: str, placeholder: str, original: str) -> None:
        with self._locked():
            self._vault_for(session_id).set(placeholder, original)

    def get_vault_entry(self, session_id: str, placeholder: str) -> str | None:
        with self._locked():
            vault = self._vaults.get(session_id)
            return vault.get(placeholder) if vault is not None else None

    def masked_counts(self, session_id: str) -> dict[str, int]:
        """Highest placeholder number per kind. Content-free; Desktop numbers after these."""
        with self._locked():
            vault = self._vaults.get(session_id)
            return vault.counts() if vault is not None else {}

    def _count_redactions(self, session_id: str, count: int) -> None:
        if count <= 0:
            return
        leases = self._read_leases()
        if session_id in leases:
            leases[session_id]["redactions"] = leases[session_id].get("redactions", 0) + count
            self._write_leases(leases)
        audit = self._read_audit()
        audit["pii_redactions"] = audit.get("pii_redactions", 0) + count
        self._write_audit(audit)

    def mask_text(self, session_id: str, text: str) -> tuple[str, list[str]]:
        """Mask one string with the session's vault. Raises if the masker fails."""
        with self._locked():
            return pii.mask_text(text, self._vault_for(session_id))

    def mask_messages_in_place(self, session_id: str, messages: list[Any]) -> int:
        """Mask the conversation Hermes is about to use for this turn, in place.

        ``pre_llm_call`` receives the turn's message dicts before titling, turn-start compaction,
        memory prefetch, and persistence read them, so masking them here keeps the original values out
        of those paths too. Raises if the masker fails; the caller then blocks the turn.
        """
        if not self.masking_active(session_id) or not isinstance(messages, list):
            return 0
        total = 0
        with self._locked():
            vault = self._vault_for(session_id)
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                for text in pii.iter_strings(msg):
                    vault.reserve(text)
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                total += self._mask_message_dict(msg, vault)
            self._count_redactions(session_id, total)
        return total

    @staticmethod
    def _mask_message_dict(msg: dict[str, Any], vault: pii.Vault) -> int:
        count = 0
        content = msg.get("content")
        if isinstance(content, str):
            masked, kinds = pii.mask_text(content, vault)
            if kinds:
                msg["content"] = masked
                count += len(kinds)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    masked, kinds = pii.mask_text(part["text"], vault)
                    if kinds:
                        part["text"] = masked
                        count += len(kinds)
        for call in msg.get("tool_calls") or []:
            fn = call.get("function") if isinstance(call, dict) else None
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                masked, kinds = pii.mask_text(fn["arguments"], vault)
                if kinds:
                    fn["arguments"] = masked
                    count += len(kinds)
        meta = msg.get("display_metadata")
        if isinstance(meta, dict):
            for key, value in list(meta.items()):
                if isinstance(value, str):
                    masked, kinds = pii.mask_text(value, vault)
                    if kinds:
                        meta[key] = masked
                        count += len(kinds)
        return count

    def mask_tool_result(self, session_id: str, result: Any) -> str | None:
        """Mask a tool result before Hermes appends it to the conversation (and stores it)."""
        if result is None or not self.masking_active(session_id):
            return None
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        with self._locked():
            masked, kinds = pii.mask_text(text, self._vault_for(session_id))
            self._count_redactions(session_id, len(kinds))
        return masked if (kinds or not isinstance(result, str)) else None

    def _strict_strip(self, request: dict[str, Any]) -> bool:
        changed = False

        def walk(node: Any, key: str | None = None) -> Any:
            nonlocal changed
            if isinstance(node, str):
                if key in ("content", "text", "system", "instructions"):
                    updated = self._strip_memory_blocks(node) if re.search(r"(?i)(?:MEMORY|USER PROFILE)\s*\(", node) else node
                    if updated != node:
                        changed = True
                    return updated
                return node
            if isinstance(node, list):
                return [walk(item, key) for item in node]
            if isinstance(node, dict):
                return {k: (v if pii.skip_key(k, v) else walk(v, k)) for k, v in node.items()}
            return node

        for top in ("system", "instructions", "messages", "input"):
            if top in request:
                request[top] = walk(request[top], top if top in ("system", "instructions") else None)
        return changed

    def transform_llm_request(self, session_id: str, request: dict[str, Any]) -> dict[str, Any] | None:
        """Sanitize LLM requests: strip profile memory (strict), mask personal details, add ZDR hints.

        Never raises. If masking fails, the request is replaced with a content-free stub and the
        execution gate (:meth:`guard_outbound`) refuses to send it.
        """
        if not session_id or not isinstance(request, dict):
            return None
        # A saved chat inside its undo window is no longer Incognito but keeps masking.
        if not self.is_incognito(session_id) and not self.masking_active(session_id):
            return None
        try:
            return self._transform_llm_request(session_id, request)
        except Exception as exc:
            logger.warning("Incognito masking failed (%s); this request will not be sent.", type(exc).__name__)
            return {"request": {"model": request.get("model"), "messages": []},
                    "source": "incognito", "reason": "masking_failed"}

    def _transform_llm_request(self, session_id: str, request: dict[str, Any]) -> dict[str, Any] | None:
        with self._locked():
            lease = self._read_leases().get(session_id) or {}
            mode = lease.get("mode", "standard")
            settings = self.get_settings()
            reasons: list[str] = []
            new_req = copy.deepcopy(request)

            if mode == "strict" and self._strict_strip(new_req):
                reasons.append("stripped_profile_memory")

            if self.masking_active(session_id):
                report = pii.MaskReport()
                new_req = pii.mask_payload(new_req, self._vault_for(session_id), report)
                if report.masked:
                    reasons.append("redacted_outbound_pii")
                    self._count_redactions(session_id, report.masked)
                if report.withheld:
                    reasons.append("withheld_attachments")

            if settings.get("provider_zdr_hints", True) and lease:
                base_url = str(request.get("base_url", "")).lower()
                if "openrouter" in base_url:
                    extra_body = new_req.get("extra_body")
                    if not isinstance(extra_body, dict):
                        extra_body = {}
                    provider = extra_body.get("provider")
                    if not isinstance(provider, dict):
                        provider = {}
                    if provider.get("data_collection") != "deny":
                        provider["data_collection"] = "deny"
                        extra_body["provider"] = provider
                        new_req["extra_body"] = extra_body
                        reasons.append("zdr_hint_openrouter")
                if "store" in request and request.get("store") is not False:
                    new_req["store"] = False
                    reasons.append("zdr_hint_store_false")

            if new_req != request:
                return {"request": new_req, "source": "incognito",
                        "reason": ",".join(reasons) if reasons else "modified"}
            return None

    def guard_outbound(self, session_id: str, request: Any) -> tuple[Any, str | None]:
        """Final check on the exact payload about to be sent.

        Returns ``(payload, None)`` to send ``payload`` (``None`` means unchanged), or
        ``(None, message)`` to block. Masks once more, then re-scans: any detectable personal detail,
        any value the vault already holds, or any unreadable attachment blocks the send.
        """
        if not self.masking_active(session_id):
            return None, None
        blocked = ("Incognito didn't send this message because it couldn't confirm your personal "
                   "details were masked.")
        try:
            with self._locked():
                vault = self._vault_for(session_id)
                report = pii.MaskReport()
                masked = pii.mask_payload(request, vault, report)
                problems = pii.verify_payload(masked, vault)
                self._count_redactions(session_id, report.masked)
        except Exception as exc:
            logger.warning("Incognito masking check failed (%s); request blocked.", type(exc).__name__)
            return None, blocked
        if problems:
            logger.warning("Incognito blocked a request: %s", ", ".join(problems))
            return None, f"{blocked} ({', '.join(problems)})"
        return masked, None

    # -------------------------------------------------------------------------
    # 19. transform_llm_response
    # -------------------------------------------------------------------------

    def transform_llm_response(self, session_id: str, response: Any) -> Any:
        """Model replies are left as sent: placeholders are never swapped back for the originals.

        Hermes stores replies in the transcript and passes tool-call arguments to tools, so restoring
        originals here would write them to disk or hand them to services outside this computer.
        Desktop shows which value each placeholder stands for, from memory, on this computer only.
        """
        return None

    # -------------------------------------------------------------------------
    # 20. Sub-agents
    # -------------------------------------------------------------------------

    def adopt_subagent(self, parent_session_id: str, child_session_id: str) -> dict[str, Any]:
        """A sub-agent of an Incognito chat is Incognito too, with the same masking and vault.

        The child is recorded as part of the parent's lineage, so it is deleted when the parent is,
        and kept when the parent is kept.
        """
        if not (_valid_session_id(parent_session_id) and _valid_session_id(child_session_id)):
            return {"ok": False, "error": "Invalid session ID."}
        if parent_session_id == child_session_id:
            return {"ok": False, "error": "A sub-agent needs its own session ID."}
        with self._locked():
            leases = self._read_leases()
            parent = leases.get(parent_session_id)
            record = self._saved_record(parent_session_id) if not isinstance(parent, dict) else None
            if record:
                parent = record["leases"][parent_session_id]
            if not isinstance(parent, dict):
                return {"ok": True, "adopted": False}
            now = time.time()
            child = {
                "session_id": child_session_id,
                "mode": parent.get("mode", "standard"),
                "redact_pii": parent.get("redact_pii", False),
                "ttl_minutes": parent.get("ttl_minutes", 0),
                "started_at": now,
                "last_activity": now,
                "expires_at": None,
                "owner_pid": os.getpid(),
                "blocked_writes": 0,
                "redactions": 0,
                "lineage_ids": [child_session_id],
                "compacted_into": parent_session_id,
                "subagent_of": parent_session_id,
            }
            if record:
                root_id = record["session_id"]
                child["redact_pii"] = bool(record.get("redact_pii"))
                self._add_subagent_lease(record["leases"], root_id, child)
                saved = self._read_saved()
                saved[root_id] = record
                self._write_saved(saved)
                self._vaults[child_session_id] = self._vault_for(root_id)
                return {"ok": True, "adopted": False, "masking": child["redact_pii"]}

            root_id = _live_head_for(leases, parent_session_id) or parent_session_id
            self._add_subagent_lease(leases, root_id, child)
            self._write_leases(leases)
            self._vaults[child_session_id] = self._vault_for(parent_session_id)
        self.ensure_hidden_in_db(child_session_id)
        return {"ok": True, "adopted": True, "session_id": child_session_id}

    @staticmethod
    def _add_subagent_lease(leases: dict[str, Any], root_id: str, child: dict[str, Any]) -> None:
        child_id = child["session_id"]
        root = leases[root_id]
        root["lineage_ids"] = sorted(set(root.get("lineage_ids", [])) | {child_id})
        leases[child_id] = child

    # -------------------------------------------------------------------------
    # 21. Save an Incognito chat, with undo
    # -------------------------------------------------------------------------

    def _saved_path(self) -> Path:
        return self.data_dir / "saved.json"

    def _read_saved(self) -> dict[str, Any]:
        data = read_json_or_empty(self._saved_path())
        return data if isinstance(data, dict) else {}

    def _write_saved(self, saved: dict[str, Any]) -> None:
        atomic_json_write(self._saved_path(), saved)

    def _saved_record(self, session_id: str) -> dict[str, Any] | None:
        """The undo record of a chat saved from Incognito, while undo is still available."""
        if not session_id:
            return None
        with self._locked():
            saved = self._read_saved()
            rec = saved.get(session_id)
            if not isinstance(rec, dict):
                rec = next((
                    candidate for candidate in saved.values()
                    if isinstance(candidate, dict) and session_id in (candidate.get("leases") or {})
                ), None)
            if rec is None:
                return None
            if time.time() >= float(rec.get("undo_until") or 0):
                self._finish_save(rec["session_id"])
                return None
            return rec

    def _finish_save(self, session_id: str) -> None:
        with self._locked():
            saved = self._read_saved()
            rec = saved.pop(session_id, None)
            if rec is None:
                return
            self._write_saved(saved)
            active = self._read_leases()
            for sid in {session_id, *(rec.get("leases") or {}), *(rec.get("subagents") or [])} - active.keys():
                self._drop_vault(sid)

    def save_session(self, session_id: str) -> dict[str, Any]:
        """Move an Incognito chat to normal history and stop its auto-delete timer.

        Keeps an undo record (IDs, times, and lease settings) for ``save_undo_minutes``
        or until the chat is closed.
        While undo is available, masking stays on if it was on, and memory and skill writes stay
        blocked, so undo can return the chat to Incognito without anything left outside it.
        """
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}
        with self._locked():
            leases = self._read_leases()
            lease = leases.get(session_id)
            if not isinstance(lease, dict):
                return {"ok": False, "error": "This chat is not in Incognito."}
            if lease.get("pending_burn"):
                return {"ok": False, "error": "This chat is already being deleted."}
            if _is_ancestor_lease(lease):
                return {"ok": False, "error": "Save the current chat, not an earlier part of it."}
            members = [session_id] + [
                sid for sid in lease.get("lineage_ids", [])
                if sid != session_id and _is_ancestor_lease(leases.get(sid)) and not leases[sid].get("pending_burn")
            ]
            snapshot = {sid: dict(leases[sid]) for sid in members}
            masking_was_on = self.masking_active(session_id)
            minutes = max(1, int(self.get_settings().get("save_undo_minutes", 10) or 10))
            now = time.time()
            record = {
                "session_id": session_id,
                "saved_at": now,
                "undo_until": now + minutes * 60,
                "mode": lease.get("mode", "standard"),
                "redact_pii": masking_was_on,
                "leases": snapshot,
            }
            saved = self._read_saved()
            # Keep the lease until both the undo record and the history update are durable.
            try:
                self._write_saved({**saved, session_id: record})
                if not self._set_history_state(dict.fromkeys(snapshot)):
                    self._write_saved(saved)
                    return {"ok": False, "error": "Could not save the chat to history. Try again."}
                try:
                    self._write_leases({sid: entry for sid, entry in leases.items() if sid not in snapshot})
                except OSError:
                    if self._set_history_state(snapshot):
                        self._write_saved(saved)
                    raise
            except OSError:
                return {"ok": False, "error": "Could not finish saving the chat. Try again."}
            return {
                "ok": True,
                "session_id": session_id,
                "saved": self.saved_state(session_id),
                "mode": "off",
                "undo_until": record["undo_until"],
                "undo_seconds": minutes * 60,
                "redact_pii": record["redact_pii"],
            }

    def undo_save(self, session_id: str) -> dict[str, Any]:
        """Return a just-saved chat to Incognito with its lineage, TTL, and masking settings."""
        if not _valid_session_id(session_id):
            return {"ok": False, "error": "Invalid session ID."}
        with self._locked():
            rec = self._saved_record(session_id)
            if rec is None or rec.get("session_id") != session_id:
                return {"ok": False, "error": "Undo is no longer available for this chat."}
            leases = self._read_leases()
            if session_id in leases:
                return {"ok": False, "error": "This chat is already in Incognito or being deleted."}
            now = time.time()
            restored: dict[str, dict[str, Any]] = {}
            for sid, snap in (rec.get("leases") or {}).items():
                if not _valid_session_id(sid) or not isinstance(snap, dict):
                    continue
                lease = dict(snap)
                lease["session_id"] = sid
                lease.pop("pending_burn", None)
                # Undo can run in a short-lived CLI process. The next real turn claims ownership.
                lease.pop("owner_pid", None)
                if not _is_ancestor_lease(lease):
                    lease["last_activity"] = now
                    ttl = lease.get("ttl_minutes", 0) or 0
                    lease["expires_at"] = now + ttl * 60 if ttl > 0 else None
                leases[sid] = lease
                restored[sid] = lease
            if not self._set_history_state(restored):
                return {"ok": False, "error": "Could not restore Incognito in chat history. Try again."}
            try:
                self._write_leases(leases)
            except OSError:
                return {"ok": False, "error": "Could not finish restoring Incognito. Try again."}
            saved = self._read_saved()
            saved.pop(session_id, None)
            try:
                self._write_saved(saved)
            except OSError:
                logger.warning("Could not remove the completed Incognito undo record")
            head = restored.get(session_id, {})
            return {
                "ok": True,
                "session_id": session_id,
                "restored": True,
                "mode": head.get("mode", "standard"),
                "redact_pii": bool(head.get("redact_pii")),
                "ttl_minutes": head.get("ttl_minutes", 0),
            }

    def end_save_undo(self, session_id: str) -> None:
        """Closing a saved chat ends its undo window."""
        if session_id and isinstance(self._read_saved().get(session_id), dict):
            self._finish_save(session_id)

    def saved_state(self, session_id: str) -> dict[str, Any] | None:
        with self._locked():
            if self.is_incognito(session_id):
                return None
            rec = self._saved_record(session_id)
            if rec is None or rec.get("session_id") != session_id:
                return None
        return {
            "session_id": session_id,
            "saved_at": rec.get("saved_at"),
            "undo_until": rec.get("undo_until"),
            "undo_remaining_seconds": max(0, int(float(rec.get("undo_until") or 0) - time.time())),
            "mode": rec.get("mode"),
            "redact_pii": bool(rec.get("redact_pii")),
        }

    def propagate_saved_compaction(self, old_session_id: str, new_session_id: str) -> bool:
        """A saved chat compacted during its undo window: undo now restores the new head too."""
        with self._locked():
            rec = self._saved_record(old_session_id)
            if rec is None or not _valid_session_id(new_session_id):
                return False
            saved = self._read_saved()
            root_id = rec["session_id"]
            leases = rec["leases"]
            head = dict(leases.get(old_session_id) or {})
            lineage = sorted(set(list(head.get("lineage_ids") or []) + [old_session_id, new_session_id]))
            old_lease = dict(head)
            old_lease["compacted_into"] = new_session_id
            old_lease["expires_at"] = None
            old_lease["lineage_ids"] = sorted(set(lineage) - {new_session_id})
            new_lease = dict(head)
            new_lease.pop("compacted_into", None)
            new_lease["session_id"] = new_session_id
            new_lease["lineage_ids"] = lineage
            leases[old_session_id] = old_lease
            leases[new_session_id] = new_lease
            rec["leases"] = leases
            if old_session_id == root_id:
                rec["session_id"] = new_session_id
                saved.pop(old_session_id, None)
                saved[new_session_id] = rec
            else:
                new_lease["compacted_into"] = old_lease.get("subagent_of") or root_id
                new_lease["expires_at"] = None
                self._add_subagent_lease(leases, root_id, new_lease)
                saved[root_id] = rec
            self._write_saved(saved)
            if old_session_id in self._vaults:
                self._vaults[new_session_id] = self._vaults[old_session_id]
            return True


# -----------------------------------------------------------------------------
# Module Singleton Management
# -----------------------------------------------------------------------------

_ENGINE_LOCK = threading.Lock()
_ENGINE_INSTANCE: IncognitoEngine | None = None
_ENGINE_HOME: str | None = None


def get_engine(home_dir: Path | str | None = None) -> IncognitoEngine:
    """Retrieve or create the IncognitoEngine singleton."""
    global _ENGINE_INSTANCE, _ENGINE_HOME
    current_home = str(Path(home_dir).expanduser().resolve()) if home_dir else os.environ.get("HERMES_HOME", "")
    with _ENGINE_LOCK:
        if _ENGINE_INSTANCE is None or (current_home and current_home != _ENGINE_HOME):
            _ENGINE_INSTANCE = IncognitoEngine(home_dir=home_dir)
            _ENGINE_HOME = current_home
        return _ENGINE_INSTANCE


def reset_engine() -> None:
    """Reset the cached engine singleton."""
    global _ENGINE_INSTANCE, _ENGINE_HOME
    with _ENGINE_LOCK:
        _ENGINE_INSTANCE = None
        _ENGINE_HOME = None
