"""Model-facing tools for the Incognito privacy plugin.

Provides incognito_control and incognito_verify tools for controlling
session privacy boundaries and auditing residual forensic traces.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

try:
    from gateway.session_context import get_session_env
except ImportError:
    def get_session_env(name: str = "", default: str = "") -> str:
        return default

try:
    from .engine import get_engine
    from .schemas import INCOGNITO_CONTROL_SCHEMA, INCOGNITO_VERIFY_SCHEMA
except (ImportError, ValueError):
    from engine import get_engine
    from schemas import INCOGNITO_CONTROL_SCHEMA, INCOGNITO_VERIFY_SCHEMA


def _resolve_active_sid(kwargs: dict[str, Any]) -> str:
    """Resolve only the caller's active runtime session ID (never model-supplied args)."""
    sid = str(
        kwargs.get("session_id")
        or kwargs.get("conversation_id")
        or kwargs.get("task_id")
        or ""
    ).strip()
    if not sid:
        try:
            sid = str(
                get_session_env("HERMES_SESSION_ID")
                or get_session_env("HERMES_SESSION_KEY")
                or ""
            ).strip()
        except Exception:
            sid = ""
    return sid


def _resolve_sid(payload: dict[str, Any], kwargs: dict[str, Any]) -> str:
    sid = str(payload.get("session_id") or "").strip()
    if sid:
        return sid
    return _resolve_active_sid(kwargs)


def incognito_control(args: Optional[dict[str, Any]] = None, **kwargs: Any) -> str:
    """Inspect or alter incognito privacy states, arming tokens, and manual burns."""
    try:
        payload: dict[str, Any] = {}
        if isinstance(args, dict):
            payload.update(args)
        elif isinstance(args, str) and args.strip():
            payload["action"] = args.strip()
        for k in ("action", "mode", "ttl_minutes", "redact_pii", "disable_action", "keep"):
            if k in kwargs and k not in payload:
                payload[k] = kwargs[k]

        sid = _resolve_active_sid(kwargs)
        engine = get_engine()
        action_clean = str(payload.get("action") or "status").strip().lower()
        mode = str(payload.get("mode") or "standard").strip().lower()
        ttl_raw = payload.get("ttl_minutes")
        ttl_minutes = int(ttl_raw) if ttl_raw is not None else None
        redact_pii = payload.get("redact_pii")
        if redact_pii is not None:
            redact_pii = bool(redact_pii)

        disable_action = str(payload.get("disable_action") or "").strip().lower()
        if not disable_action:
            disable_action = "keep" if payload.get("keep", True) else "burn"

        result: dict[str, Any]
        if action_clean == "status":
            result = engine.status_summary(session_id=sid)
        elif action_clean in ("enable", "on"):
            if not sid:
                result = engine.arm_next_session(mode=mode, ttl_minutes=ttl_minutes, redact_pii=redact_pii)
            else:
                result = engine.enable_session(
                    session_id=sid, mode=mode, ttl_minutes=ttl_minutes, redact_pii=redact_pii
                )
        elif action_clean in ("disable", "off"):
            if not sid or not engine.is_incognito(sid):
                result = {"ok": False, "error": "Active session is not in incognito mode"}
            else:
                result = engine.disable_session(session_id=sid, action=disable_action)
        elif action_clean == "toggle":
            if not sid:
                armed = engine.get_armed_state()
                result = (
                    engine.disarm_next_session()
                    if armed
                    else engine.arm_next_session(mode=mode, ttl_minutes=ttl_minutes, redact_pii=redact_pii)
                )
            else:
                result = engine.toggle_session(session_id=sid, mode=mode, ttl_minutes=ttl_minutes)
        elif action_clean == "burn":
            if not sid or not engine.is_incognito(sid):
                result = {"ok": False, "error": "Active session is not in incognito mode"}
            else:
                result = engine.burn_session(session_id=sid, reason="tool_control_burn")
        elif action_clean == "arm":
            result = engine.arm_next_session(mode=mode, ttl_minutes=ttl_minutes, redact_pii=redact_pii)
        elif action_clean == "disarm":
            result = engine.disarm_next_session()
        elif action_clean == "sweep":
            result = engine.sweep_expired()
        elif action_clean == "ttl":
            if not sid:
                result = {"ok": False, "error": "session_id is required to update TTL"}
            elif ttl_minutes is None:
                result = {"ok": False, "error": "ttl_minutes parameter is required"}
            else:
                result = engine.set_session_ttl(sid, ttl_minutes)
        else:
            result = {"ok": False, "error": f"Unknown incognito_control action '{action_clean}'"}

        return json.dumps(result)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)})


def incognito_verify(args: Optional[dict[str, Any]] = None, **kwargs: Any) -> str:
    """Verify zero residual trace in SQLite, transcript files, and RAM for a session."""
    try:
        payload: dict[str, Any] = {}
        if isinstance(args, dict):
            payload.update(args)
        elif isinstance(args, str) and args.strip():
            payload["session_id"] = args.strip()
        if "session_id" in kwargs and "session_id" not in payload:
            payload["session_id"] = kwargs["session_id"]

        sid = _resolve_sid(payload, kwargs)
        if not sid:
            return json.dumps({"ok": False, "error": "session_id is required to verify zero trace"})

        engine = get_engine()
        return json.dumps(engine.verify_zero_trace(sid))
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)})
