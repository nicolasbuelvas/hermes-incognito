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
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

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
_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


def _is_valid_session_id(session_id: Any) -> bool:
    """Validate session_id against a strict filename-safe pattern (no '/', '\\', '..', or roots)."""
    if not isinstance(session_id, str) or not session_id or len(session_id) > 256:
        return False
    if "/" in session_id or "\\" in session_id or ".." in session_id or "\x00" in session_id:
        return False
    p = Path(session_id)
    if p.is_absolute() or p.drive or p.root or p.name != session_id:
        return False
    return bool(_SAFE_SESSION_ID_RE.fullmatch(session_id))


def _session_exact_filenames(target_ids: set[str]) -> set[str]:
    """Exact transcript/snapshot filenames for target session IDs in $HERMES_HOME/sessions/."""
    names: set[str] = set()
    for sid in target_ids:
        if _is_valid_session_id(sid):
            names.update((f"{sid}.jsonl", f"{sid}.json", f"session_{sid}.json", f"session_{sid}.jsonl"))
    return names


def _hook_exact_filenames(target_ids: set[str]) -> set[str]:
    """Exact flat hook-output filenames for target session IDs in $HERMES_HOME/hook_outputs/."""
    names: set[str] = set()
    for sid in target_ids:
        if _is_valid_session_id(sid):
            names.update((f"{sid}.txt", f"{sid}.json", f"{sid}.jsonl"))
    return names

# Common PII and credential patterns for in-RAM reversible vault
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_PATTERN = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_BEARER_PATTERN = re.compile(r"\bBearer\s+([A-Za-z0-9_\-\.~+/=]{20,})\b")
_SECRET_ASSIGN_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.~+/=]{16,})[\"']?"
)

# Strict clean-room memory stripping patterns
_STRICT_MEMORY_BLOCKS = re.compile(
    r"(?is)(?:MEMORY|USER PROFILE)\s*\([^)]*\):?.*?(?=\n\n|\Z)|#{1,3}\s*(?:MEMORY|USER PROFILE)\b.*?(?=\n#{1,3}\s|\Z)"
)


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
        except (ProcessLookupError, PermissionError):
            return False
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


class IncognitoEngine:
    """Core runtime engine managing zero-trace incognito state and sanitization."""

    def __init__(self, home_dir: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self._explicit_home = Path(home_dir).expanduser().resolve() if home_dir else None
        self.config: dict[str, Any] = {}
        # RAM-only reversible PII vaults: session_id -> {placeholder: original}
        self._vaults: dict[str, dict[str, str]] = {}
        # Reverse mapping: session_id -> {original: placeholder}
        self._reverse_vaults: dict[str, dict[str, str]] = {}
        # Kind counters: session_id -> {kind: count}
        self._kind_counters: dict[str, dict[str, int]] = {}

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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            self._write_armed(None)
            return {"ok": True, "armed": None}

    # -------------------------------------------------------------------------
    # 4. get_armed_state
    # -------------------------------------------------------------------------

    def get_armed_state(self) -> dict[str, Any] | None:
        """Inspect pending armed incognito configuration."""
        with self._lock:
            return self._read_armed()

    # -------------------------------------------------------------------------
    # 5. consume_armed_session
    # -------------------------------------------------------------------------

    def consume_armed_session(self, session_id: str) -> dict[str, Any] | None:
        """Activate incognito mode for session_id if armed or default_mode is active."""
        if not session_id:
            return None
        with self._lock:
            leases = self._read_leases()
            if session_id in leases:
                return leases[session_id]

            armed = self._read_armed()
            settings = self.get_settings()
            default_mode = settings.get("default_mode", "off")

            if armed:
                self._write_armed(None)
                res = self.enable_session(
                    session_id=session_id,
                    mode=armed.get("mode", "standard"),
                    ttl_minutes=armed.get("ttl_minutes"),
                    redact_pii=armed.get("redact_pii"),
                )
                return res.get("lease")
            elif default_mode in ("standard", "strict"):
                res = self.enable_session(
                    session_id=session_id,
                    mode=default_mode,
                    ttl_minutes=settings.get("default_ttl_minutes"),
                    redact_pii=settings.get("redact_outbound_pii"),
                )
                return res.get("lease")
            return None

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
        """Enable incognito mode for a session, hiding it in SQLite and registering lease."""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")
        if not _is_valid_session_id(session_id):
            raise ValueError("Invalid session_id format")
        if mode not in ("standard", "strict"):
            raise ValueError(f"Invalid mode '{mode}': must be 'standard' or 'strict'")

        with self._lock:
            settings = self.get_settings()
            ttl = ttl_minutes if ttl_minutes is not None else settings.get("default_ttl_minutes", 60)
            redact = redact_pii if redact_pii is not None else settings.get("redact_outbound_pii", False)
            now = time.time()
            expires_at = now + (ttl * 60) if ttl > 0 else None

            lease = {
                "session_id": session_id,
                "mode": mode,
                "ttl_minutes": ttl,
                "owner_pid": os.getpid(),
                "started_at": now,
                "last_activity": now,
                "expires_at": expires_at,
                "redact_pii": redact,
                "blocked_writes": 0,
                "redactions": 0,
                "lineage_ids": [session_id],
            }

            # Update SessionDB if available
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

            leases = self._read_leases()
            leases[session_id] = lease
            self._write_leases(leases)

            audit = self._read_audit()
            audit["sessions_protected"] = audit.get("sessions_protected", 0) + 1
            self._write_audit(audit)

            return {"ok": True, "session_id": session_id, "mode": mode, "lease": lease}

    # -------------------------------------------------------------------------
    # 7. disable_session
    # -------------------------------------------------------------------------

    def disable_session(self, session_id: str, action: str = "keep") -> dict[str, Any]:
        """Disable incognito mode, keeping or immediately burning residual state."""
        if not session_id:
            raise ValueError("session_id must be a non-empty string")

        if action == "burn":
            return self.burn_session(session_id, reason="disable_burn")

        with self._lock:
            state_db = self.home_dir / "state.db"
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        db.set_session_hidden(session_id, False)
                        db.patch_session_model_config(session_id, {"incognito": None})
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception:
                    pass

            leases = self._read_leases()
            leases.pop(session_id, None)
            self._write_leases(leases)

            # Clear in-RAM vaults
            self._vaults.pop(session_id, None)
            self._reverse_vaults.pop(session_id, None)
            self._kind_counters.pop(session_id, None)

            return {"ok": True, "session_id": session_id, "mode": "off", "action": "keep"}

    def set_session_ttl(self, session_id: str, ttl_minutes: int) -> dict[str, Any]:
        """Update inactivity TTL in minutes for an active incognito session."""
        if not session_id:
            return {"ok": False, "error": "session_id is required"}
        with self._lock:
            leases = self._read_leases()
            if session_id not in leases:
                return {"ok": False, "error": f"Session '{session_id}' is not currently incognito"}
            leases[session_id]["ttl_minutes"] = int(ttl_minutes)
            now = time.time()
            leases[session_id]["expires_at"] = now + (int(ttl_minutes) * 60) if int(ttl_minutes) > 0 else None
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
        self, session_id: str, mode: str = "standard", ttl_minutes: int | None = None
    ) -> dict[str, Any]:
        """Toggle incognito mode, disable when mode=='off', or switch mode in place."""
        clean_mode = (mode or "standard").strip().lower()
        if clean_mode == "off":
            return self.disable_session(session_id, action="keep")
        if self.is_incognito(session_id):
            current = self.get_session_state(session_id)
            if current and current.get("mode") != clean_mode and clean_mode in ("standard", "strict"):
                return self.enable_session(session_id, mode=clean_mode, ttl_minutes=ttl_minutes)
            return self.disable_session(session_id, action="keep")
        return self.enable_session(session_id, mode=clean_mode, ttl_minutes=ttl_minutes)

    # -------------------------------------------------------------------------
    # 9. is_incognito
    # -------------------------------------------------------------------------

    def is_incognito(self, session_id: str) -> bool:
        """Check if a session is currently running under incognito protection."""
        if not session_id:
            return False
        with self._lock:
            leases = self._read_leases()
            lease = leases.get(session_id)
            return bool(lease and not lease.get("pending_burn"))

    def get_protected_session_ids(self) -> set[str]:
        """Return all session IDs protected from cross-session search (active or pending burn)."""
        with self._lock:
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

        with self._lock:
            leases = self._read_leases()
            lease = leases.get(session_id)
            if not lease:
                return None

            expires_at = lease.get("expires_at")
            remaining = max(0, int(expires_at - time.time())) if expires_at else None

            return {
                "active": True,
                "session_id": session_id,
                "mode": lease.get("mode", "standard"),
                "hidden": True,
                "ttl_minutes": lease.get("ttl_minutes", 0),
                "expires_at": expires_at,
                "remaining_seconds": remaining,
                "blocked_writes": lease.get("blocked_writes", 0),
                "redactions": lease.get("redactions", 0),
                "redact_pii": lease.get("redact_pii", False),
                "started_at": lease.get("started_at"),
            }

    # -------------------------------------------------------------------------
    # 11. touch_session
    # -------------------------------------------------------------------------

    def ensure_hidden_in_db(self, session_id: str) -> None:
        """Ensure an active incognito session stays hidden in SessionDB after turn writes."""
        if not session_id:
            return
        with self._lock:
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
        with self._lock:
            leases = self._read_leases()
            if session_id in leases:
                now = time.time()
                leases[session_id]["last_activity"] = now
                ttl = leases[session_id].get("ttl_minutes", 0)
                if ttl > 0:
                    leases[session_id]["expires_at"] = now + (ttl * 60)
                self._write_leases(leases)

    # -------------------------------------------------------------------------
    # 12. propagate_compaction
    # -------------------------------------------------------------------------

    def propagate_compaction(self, old_session_id: str, new_session_id: str) -> dict[str, Any]:
        """Propagate incognito lease and vault state across session compaction chains."""
        if not old_session_id or not new_session_id:
            return {"ok": False, "error": "both old and new session IDs are required"}

        with self._lock:
            leases = self._read_leases()
            old_lease = leases.get(old_session_id)
            if not old_lease:
                return {"ok": True, "propagated": False, "session_id": new_session_id}

            new_lease = dict(old_lease)
            new_lease["session_id"] = new_session_id
            existing_lineage = old_lease.get("lineage_ids", [old_session_id])
            combined_lineage = sorted(list(set(existing_lineage + [old_session_id, new_session_id])))
            new_lease["lineage_ids"] = combined_lineage
            old_lease["lineage_ids"] = combined_lineage

            # Clone in-RAM vault
            if old_session_id in self._vaults:
                self._vaults[new_session_id] = dict(self._vaults[old_session_id])
            if old_session_id in self._reverse_vaults:
                self._reverse_vaults[new_session_id] = dict(self._reverse_vaults[old_session_id])
            if old_session_id in self._kind_counters:
                self._kind_counters[new_session_id] = dict(self._kind_counters[old_session_id])

            leases[new_session_id] = new_lease
            leases[old_session_id] = old_lease
            self._write_leases(leases)

            # Update SessionDB
            state_db = self.home_dir / "state.db"
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        db.set_session_hidden(new_session_id, True)
                        db.patch_session_model_config(new_session_id, {"incognito": new_lease})
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

    def _count_db_rows_for_ids(self, state_db: Path, target_ids: set[str]) -> int:
        """Count remaining rows across sessions and messages tables for target_ids."""
        if not state_db.is_file() or not target_ids:
            return 0
        total = 0
        try:
            conn = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
            try:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
                if cur.fetchone():
                    for sid in target_ids:
                        row_s = cur.execute("SELECT count(*) FROM sessions WHERE id = ?", (sid,)).fetchone()
                        if row_s:
                            total += int(row_s[0])
                        row_m = cur.execute("SELECT count(*) FROM messages WHERE session_id = ?", (sid,)).fetchone()
                        if row_m:
                            total += int(row_m[0])
            finally:
                conn.close()
        except Exception:
            pass
        return total

    def _schedule_deferred_burn(self, session_id: str, attempt: int = 1) -> None:
        """Retry burning a busy session once its active Gateway turn admission settles."""
        delays = {1: 1.5, 2: 5.0, 3: 15.0}
        delay = delays.get(attempt)
        if delay is None:
            return

        def _retry() -> None:
            try:
                with self._lock:
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

    def burn_session(
        self, session_id: str, reason: str = "burn", *, _retry_attempt: int = 0
    ) -> dict[str, Any]:
        """Perform zero-trace scrub of SQLite rows, transcript files, and RAM vault."""
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")
        if not _is_valid_session_id(session_id):
            return {
                "ok": False,
                "session_id": session_id,
                "error": "Invalid session_id format",
            }

        with self._lock:
            leases = self._read_leases()
            raw_lease = leases.get(session_id)
            has_incognito_lease = isinstance(raw_lease, dict)

            state_db = self.home_dir / "state.db"
            has_db_incognito_tag = False
            db_delete_targets: list[str] = []
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        if not has_incognito_lease:
                            if hasattr(db, "get_session_model_config_value"):
                                has_db_incognito_tag = bool(
                                    db.get_session_model_config_value(session_id, "incognito")
                                )
                            if not has_db_incognito_tag and hasattr(db, "session_ids_with_model_config_key"):
                                has_db_incognito_tag = session_id in db.session_ids_with_model_config_key(
                                    "incognito"
                                )
                            if not has_db_incognito_tag and hasattr(db, "get_session"):
                                row = db.get_session(session_id)
                                if isinstance(row, dict) and row.get("model_config"):
                                    mc = json.loads(row["model_config"])
                                    has_db_incognito_tag = isinstance(mc, dict) and bool(mc.get("incognito"))
                        if (has_incognito_lease or has_db_incognito_tag) and hasattr(
                            db, "get_session_delete_targets"
                        ):
                            targets = db.get_session_delete_targets(session_id)
                            if targets:
                                db_delete_targets = [t for t in targets if _is_valid_session_id(t)]
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception:
                    pass

            if not has_incognito_lease and not has_db_incognito_tag:
                return {
                    "ok": False,
                    "session_id": session_id,
                    "error": f"Session '{session_id}' is not an incognito session",
                }

            lease = raw_lease if isinstance(raw_lease, dict) else {}
            target_ids: set[str] = {session_id}
            for lid in lease.get("lineage_ids", []):
                if _is_valid_session_id(lid):
                    target_ids.add(lid)
            target_ids.update(db_delete_targets)

            rows_before = self._count_db_rows_for_ids(state_db, target_ids)

            # 1. Zero-fill and unlink confined disk files (transcripts and hook outputs)
            #    before SessionDB.delete_session removes any remaining session files.
            settings = self.get_settings()
            zero_fill = settings.get("zero_fill_files", True)
            files_scrubbed = 0

            sessions_dir = self.home_dir / "sessions"
            hook_outputs_dir = self.home_dir / "hook_outputs"

            def _scrub_file(file_path: Path) -> None:
                nonlocal files_scrubbed
                try:
                    if file_path.is_file():
                        if zero_fill:
                            size = file_path.stat().st_size
                            if size > 0:
                                with open(file_path, "r+b") as f:
                                    f.write(b"\x00" * size)
                                    f.flush()
                                    try:
                                        os.fsync(f.fileno())
                                    except OSError:
                                        pass
                        file_path.unlink(missing_ok=True)
                        files_scrubbed += 1
                except Exception as exc:
                    logger.debug("Failed to scrub file %s: %s", file_path, exc)

            if sessions_dir.is_dir() and not sessions_dir.is_symlink():
                sessions_root = sessions_dir.resolve()
                exact_session_names = _session_exact_filenames(target_ids)
                for p in sessions_dir.iterdir():
                    if (
                        not p.is_symlink()
                        and p.is_file()
                        and p.name in exact_session_names
                        and p.resolve().parent == sessions_root
                    ):
                        _scrub_file(p)

            if hook_outputs_dir.is_dir() and not hook_outputs_dir.is_symlink():
                hook_root = hook_outputs_dir.resolve()
                for sid in target_ids:
                    if not _is_valid_session_id(sid):
                        continue
                    raw_sid_dir = hook_outputs_dir / sid
                    if raw_sid_dir.is_symlink():
                        continue
                    sid_dir = raw_sid_dir.resolve()
                    if sid_dir.parent != hook_root or sid_dir == hook_root:
                        continue
                    if sid_dir.is_dir():
                        for p in sid_dir.glob("**/*"):
                            if not p.is_symlink() and p.is_file() and sid_dir in p.resolve().parents:
                                _scrub_file(p)
                        try:
                            for sub in sorted(sid_dir.glob("**/*"), key=lambda x: len(x.parts), reverse=True):
                                if not sub.is_symlink() and sub.is_dir() and sid_dir in sub.resolve().parents:
                                    sub.rmdir()
                            sid_dir.rmdir()
                        except Exception:
                            pass
                exact_hook_names = _hook_exact_filenames(target_ids)
                for p in hook_outputs_dir.iterdir():
                    if (
                        not p.is_symlink()
                        and p.is_file()
                        and p.name in exact_hook_names
                        and p.resolve().parent == hook_root
                    ):
                        _scrub_file(p)

            # 2. Delete state.db rows exclusively through SessionDB.delete_session(...)
            db_deleted = False
            delete_deferred = False
            if SessionDB is not None and state_db.exists():
                try:
                    db = SessionDB(db_path=state_db)
                    try:
                        for sid in list(target_ids):
                            try:
                                if db.delete_session(
                                    sid,
                                    sessions_dir=sessions_dir,
                                    include_compression_chain=True,
                                ):
                                    db_deleted = True
                            except Exception as exc:
                                delete_deferred = True
                                logger.debug("SessionDB.delete_session deferred for %s: %s", sid, exc)
                    finally:
                        if hasattr(db, "close"):
                            db.close()
                except Exception as exc:
                    delete_deferred = True
                    logger.debug("SessionDB open failed during burn_session: %s", exc)

            rows_after = self._count_db_rows_for_ids(state_db, target_ids)
            if rows_before > 0 and rows_after == 0 and not delete_deferred:
                db_deleted = True
            elif rows_after > 0 or delete_deferred:
                db_deleted = False

            # 3. Clear RAM vault
            vault_keys_cleared = 0
            for sid in target_ids:
                v = self._vaults.pop(sid, {})
                self._reverse_vaults.pop(sid, None)
                self._kind_counters.pop(sid, None)
                vault_keys_cleared += len(v)

            # 4. Remove active leases, or retain a pending_burn tombstone if Gateway still holds
            #    an active turn admission lock on the sessions row so sweep/retry finishes it.
            pending_burn = rows_after > 0 or (delete_deferred and not db_deleted)
            if pending_burn:
                leases[session_id] = {
                    **(lease if isinstance(lease, dict) else {}),
                    "session_id": session_id,
                    "mode": lease.get("mode", "standard") if isinstance(lease, dict) else "standard",
                    "pending_burn": True,
                    "expires_at": 0,
                    "lineage_ids": sorted(target_ids),
                }
                for sid in target_ids:
                    if sid != session_id:
                        leases.pop(sid, None)
            else:
                for sid in target_ids:
                    leases.pop(sid, None)
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
                "files_scrubbed": files_scrubbed,
                "vault_keys_cleared": vault_keys_cleared,
            }

            if _retry_attempt == 0 or not pending_burn:
                audit = self._read_audit()
                if _retry_attempt == 0:
                    audit["sessions_burned"] = audit.get("sessions_burned", 0) + 1
                audit["files_scrubbed"] = audit.get("files_scrubbed", 0) + files_scrubbed
                receipts = audit.setdefault("receipts", [])
                receipts.append(receipt)
                self._write_audit(audit)

            return {
                "ok": True,
                "session_id": session_id,
                "reason": reason,
                "db_deleted": db_deleted,
                "pending_burn": pending_burn,
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
        with self._lock:
            now = time.time()
            leases = self._read_leases()
            to_burn: dict[str, str] = {}

            for sid, lease in leases.items():
                if isinstance(lease, dict) and lease.get("pending_burn"):
                    to_burn[sid] = "pending_burn_retry"
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
                        for sid in db_incognito_ids:
                            if sid not in leases and sid not in to_burn:
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
                res = self.burn_session(sid, reason=reason)
                swept_receipts.append(res)

            if to_burn:
                audit = self._read_audit()
                audit["orphans_swept"] = audit.get("orphans_swept", 0) + len(to_burn)
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
        if not session_id:
            raise ValueError("session_id must be a non-empty string")
        if not _is_valid_session_id(session_id):
            return {
                "ok": False,
                "session_id": session_id,
                "zero_trace": False,
                "error": "Invalid session_id format",
            }

        with self._lock:
            db_rows_found = 0
            state_db = self.home_dir / "state.db"

            if state_db.is_file():
                try:
                    conn = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
                    if cur.fetchone():
                        cur.execute("SELECT count(*) FROM sessions WHERE id = ?", (session_id,))
                        row = cur.fetchone()
                        if row:
                            db_rows_found += int(row[0])
                        cur.execute("SELECT count(*) FROM messages WHERE session_id = ?", (session_id,))
                        row = cur.fetchone()
                        if row:
                            db_rows_found += int(row[0])
                    conn.close()
                except Exception:
                    pass

            # Check files using confined paths and exact filename matches
            single_target = {session_id}
            session_files_found = 0
            sessions_dir = self.home_dir / "sessions"
            if sessions_dir.is_dir() and not sessions_dir.is_symlink():
                sessions_root = sessions_dir.resolve()
                exact_session_names = _session_exact_filenames(single_target)
                for p in sessions_dir.iterdir():
                    if (
                        not p.is_symlink()
                        and p.is_file()
                        and p.name in exact_session_names
                        and p.resolve().parent == sessions_root
                    ):
                        session_files_found += 1

            hook_files_found = 0
            hook_outputs_dir = self.home_dir / "hook_outputs"
            if hook_outputs_dir.is_dir() and not hook_outputs_dir.is_symlink():
                hook_root = hook_outputs_dir.resolve()
                raw_sid_dir = hook_outputs_dir / session_id
                if not raw_sid_dir.is_symlink():
                    sid_dir = raw_sid_dir.resolve()
                    if sid_dir.parent == hook_root and sid_dir != hook_root and sid_dir.is_dir():
                        hook_files_found += sum(
                            1 for p in sid_dir.glob("**/*") if not p.is_symlink() and sid_dir in p.resolve().parents
                        )
                exact_hook_names = _hook_exact_filenames(single_target)
                for p in hook_outputs_dir.iterdir():
                    if (
                        not p.is_symlink()
                        and p.is_file()
                        and p.name in exact_hook_names
                        and p.resolve().parent == hook_root
                    ):
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

    def status_summary(self, session_id: str = "") -> dict[str, Any]:
        """Aggregate system-wide status, armed state, active sessions, and audit metrics."""
        with self._lock:
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

    # -------------------------------------------------------------------------
    # 17. evaluate_tool_guard & scrub_tool_result
    # -------------------------------------------------------------------------

    def evaluate_tool_guard(
        self, session_id: str, tool_name: str, args: dict[str, Any] | None = None
    ) -> dict[str, str] | None:
        """Enforce tool execution boundaries for incognito sessions and cross-session reads."""
        with self._lock:
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
                    incog_action = str(t_args.get("action") or "status").strip().lower()
                    incog_disable = str(
                        t_args.get("disable_action") or ("keep" if t_args.get("keep", True) else "burn")
                    ).strip().lower()
                    if incog_action == "burn" or (
                        incog_action in ("disable", "off") and incog_disable == "burn"
                    ):
                        if not is_caller_incog:
                            return {
                                "action": "block",
                                "message": "Refusing to burn: active session is not in incognito mode.",
                            }
                        return {
                            "action": "approve",
                            "message": (
                                f"Confirm permanently burning active incognito session '{session_id}'?"
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
    # 18. transform_llm_request
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
            res = single_bar.sub("", res)
            res = re.sub(r"[═=\-_]{5,}\s*\n?", "", res)

        # Collapse excess blank lines left behind by removed blocks
        res = re.sub(r"\n{3,}", "\n\n", res)
        return res.strip()

    def transform_llm_request(self, session_id: str, request: dict[str, Any]) -> dict[str, Any] | None:
        """Sanitize LLM requests: strip profile memory, redact PII, and attach ZDR hints."""
        if not session_id or not isinstance(request, dict) or not self.is_incognito(session_id):
            return None

        with self._lock:
            leases = self._read_leases()
            lease = leases.get(session_id, {})
            mode = lease.get("mode", "standard")
            settings = self.get_settings()
            redact_pii = lease.get("redact_pii")
            if redact_pii is None:
                redact_pii = settings.get("redact_outbound_pii", False)

            reasons: list[str] = []
            new_req = copy.deepcopy(request)
            modified = False

            def _apply_text_transform(container: dict[str, Any], fn: Callable[[str], str], reason_tag: str) -> None:
                nonlocal modified
                # Top-level string or block-list fields (Anthropic 'system', Codex 'instructions')
                for top_key in ("system", "instructions"):
                    val = container.get(top_key)
                    if isinstance(val, str):
                        updated = fn(val)
                        if updated != val:
                            container[top_key] = updated
                            modified = True
                            if reason_tag and reason_tag not in reasons:
                                reasons.append(reason_tag)
                    elif isinstance(val, list):
                        for block in val:
                            if isinstance(block, dict) and isinstance(block.get("text"), str):
                                updated = fn(block["text"])
                                if updated != block["text"]:
                                    block["text"] = updated
                                    modified = True
                                    if reason_tag and reason_tag not in reasons:
                                        reasons.append(reason_tag)

                # Message arrays (OpenAI/Gemini 'messages', Codex Responses 'input')
                for list_key in ("messages", "input"):
                    msgs = container.get(list_key)
                    if not isinstance(msgs, list):
                        continue
                    for msg in msgs:
                        if not isinstance(msg, dict):
                            continue
                        content = msg.get("content")
                        if isinstance(content, str):
                            updated = fn(content)
                            if updated != content:
                                msg["content"] = updated
                                modified = True
                                if reason_tag and reason_tag not in reasons:
                                    reasons.append(reason_tag)
                        elif isinstance(content, list):
                            for part in content:
                                if isinstance(part, dict) and isinstance(part.get("text"), str):
                                    updated = fn(part["text"])
                                    if updated != part["text"]:
                                        part["text"] = updated
                                        modified = True
                                        if reason_tag and reason_tag not in reasons:
                                            reasons.append(reason_tag)

            # In strict mode, strip persistent memory sections from system/instructions/messages
            if mode == "strict":
                _apply_text_transform(new_req, self._strip_memory_blocks, "stripped_profile_memory")

            # Outbound PII redaction via reversible vault
            if redact_pii:
                vault = self._vaults.setdefault(session_id, {})
                reverse_vault = self._reverse_vaults.setdefault(session_id, {})
                kind_counters = self._kind_counters.setdefault(session_id, {})

                def _mask_value(original: str, kind: str) -> str:
                    nonlocal modified
                    if original in reverse_vault:
                        return reverse_vault[original]
                    kind_counters[kind] = kind_counters.get(kind, 0) + 1
                    count = kind_counters[kind]
                    placeholder = f"[REDACTED_{kind}_{count}]"
                    vault[placeholder] = original
                    reverse_vault[original] = placeholder
                    modified = True
                    return placeholder

                def _redact_text(text: str) -> str:
                    if not text:
                        return text
                    text = _EMAIL_PATTERN.sub(lambda m: _mask_value(m.group(0), "EMAIL"), text)
                    text = _PHONE_PATTERN.sub(lambda m: _mask_value(m.group(0), "PHONE"), text)
                    text = _CARD_PATTERN.sub(lambda m: _mask_value(m.group(0), "CARD"), text)
                    text = _SSN_PATTERN.sub(lambda m: _mask_value(m.group(0), "SSN"), text)
                    text = _BEARER_PATTERN.sub(lambda m: f"Bearer {_mask_value(m.group(1), 'SECRET')}", text)
                    text = _SECRET_ASSIGN_PATTERN.sub(lambda m: f"{m.group(1)}={_mask_value(m.group(2), 'SECRET')}", text)
                    return text

                redaction_count_before = len(vault)
                _apply_text_transform(new_req, _redact_text, "")

                new_redactions = len(vault) - redaction_count_before
                if new_redactions > 0:
                    if "redacted_outbound_pii" not in reasons:
                        reasons.append("redacted_outbound_pii")
                    if session_id in leases:
                        leases[session_id]["redactions"] = leases[session_id].get("redactions", 0) + new_redactions
                        self._write_leases(leases)
                    audit = self._read_audit()
                    audit["pii_redactions"] = audit.get("pii_redactions", 0) + new_redactions
                    self._write_audit(audit)

            # Provider Zero Data Retention (ZDR) hints
            if settings.get("provider_zdr_hints", True):
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
                        modified = True

                if "store" in request and request.get("store") is not False:
                    new_req["store"] = False
                    reasons.append("zdr_hint_store_false")
                    modified = True

            if modified:
                return {
                    "request": new_req,
                    "source": "incognito",
                    "reason": ",".join(reasons) if reasons else "modified",
                }
            return None

    # -------------------------------------------------------------------------
    # 19. transform_llm_response
    # -------------------------------------------------------------------------

    def transform_llm_response(self, session_id: str, response: Any) -> Any:
        """Safely restore in-RAM redacted PII placeholders in LLM responses."""
        if not session_id or response is None or not self.is_incognito(session_id):
            return None

        with self._lock:
            vault = self._vaults.get(session_id)
            if not vault:
                return response
            items = list(vault.items())

        def _restore_text(s: str) -> str:
            for placeholder, original in items:
                if placeholder in s:
                    s = s.replace(placeholder, original)
            return s

        def _restore_node(obj: Any) -> Any:
            if isinstance(obj, str):
                return _restore_text(obj)
            elif isinstance(obj, dict):
                return {k: _restore_node(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_restore_node(elem) for elem in obj]
            elif hasattr(obj, "content") and isinstance(obj.content, str):
                try:
                    obj.content = _restore_text(obj.content)
                except Exception:
                    pass
                return obj
            elif hasattr(obj, "choices") and isinstance(obj.choices, list):
                for choice in obj.choices:
                    if hasattr(choice, "message") and hasattr(choice.message, "content"):
                        if isinstance(choice.message.content, str):
                            try:
                                choice.message.content = _restore_text(choice.message.content)
                            except Exception:
                                pass
                return obj
            return obj

        try:
            return _restore_node(response)
        except Exception as exc:
            logger.debug("Failed to restore response vault values: %s", exc)
            return response


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
