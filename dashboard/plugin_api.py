from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from fastapi import APIRouter, Body, Query
except ImportError:
    class APIRouter:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def get(self, *args: Any, **kwargs: Any):
            def decorator(fn: Any) -> Any:
                return fn
            return decorator

        def post(self, *args: Any, **kwargs: Any):
            def decorator(fn: Any) -> Any:
                return fn
            return decorator

    Query = lambda default=None, **kwargs: default  # type: ignore
    Body = lambda default_factory=None, default=None, **kwargs: default if default is not None else (default_factory() if callable(default_factory) else {})  # type: ignore

router = APIRouter()


def _resolve_engine() -> Any:
    """Resolve IncognitoEngine singleton with relative and sys.path fallbacks."""
    try:
        from ..engine import get_engine
        return get_engine()
    except (ImportError, ValueError):
        parent_dir = str(Path(__file__).resolve().parent.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        try:
            from engine import get_engine
            return get_engine()
        except ImportError:
            try:
                import engine
                if hasattr(engine, "get_engine"):
                    return engine.get_engine()
                if hasattr(engine, "IncognitoEngine"):
                    return (
                        engine.IncognitoEngine.get_instance()
                        if hasattr(engine.IncognitoEngine, "get_instance")
                        else engine.IncognitoEngine()
                    )
            except ImportError:
                return None
    return None


@router.get("/status")
def get_status(session_id: str = Query("", description="Optional session id to inspect")) -> Any:
    eng = _resolve_engine()
    if eng is None:
        return {"status": "unavailable", "incognito": False, "armed": None}
    if hasattr(eng, "status_summary"):
        return eng.status_summary(session_id=session_id)
    armed = eng.get_armed_state() if hasattr(eng, "get_armed_state") else None
    active = eng.is_incognito(session_id) if (session_id and hasattr(eng, "is_incognito")) else False
    st = eng.get_session_state(session_id) if (session_id and hasattr(eng, "get_session_state")) else None
    return {
        "session_id": session_id,
        "incognito": active,
        "mode": st.get("mode") if st else (armed.get("mode") if armed else "off"),
        "session_state": st,
        "armed": armed,
    }


@router.post("/toggle")
def toggle_session(body: Dict[str, Any] = Body(default_factory=dict)) -> Any:
    eng = _resolve_engine()
    if eng is None:
        return {"ok": False, "error": "engine unavailable"}

    session_id = str(body.get("session_id") or "").strip()
    mode = str(body.get("mode") or "standard")
    ttl = body.get("ttl_minutes")
    redact = body.get("redact_pii")

    if session_id and session_id != "new":
        if hasattr(eng, "toggle_session"):
            result = eng.toggle_session(session_id, mode=mode)
            if not result["ok"]:
                return result
        elif hasattr(eng, "is_incognito") and hasattr(eng, "disable_session") and hasattr(eng, "enable_session"):
            if eng.is_incognito(session_id):
                eng.disable_session(session_id, action="keep")
            else:
                eng.enable_session(session_id, mode=mode, ttl_minutes=ttl, redact_pii=redact)
        elif hasattr(eng, "enable_session"):
            eng.enable_session(session_id, mode=mode, ttl_minutes=ttl, redact_pii=redact)
    else:
        armed = eng.get_armed_state() if hasattr(eng, "get_armed_state") else None
        if armed and hasattr(eng, "disarm_next_session"):
            eng.disarm_next_session()
        elif hasattr(eng, "arm_next_session"):
            eng.arm_next_session(mode=mode, ttl_minutes=ttl, redact_pii=redact)

    if hasattr(eng, "status_summary"):
        return eng.status_summary(session_id=session_id)
    return {"ok": True, "session_id": session_id}


@router.post("/arm")
def arm_session(body: Dict[str, Any] = Body(default_factory=dict)) -> Any:
    eng = _resolve_engine()
    if eng is None:
        return {"ok": False, "error": "engine unavailable"}

    disarm = bool(body.get("disarm", False))
    if disarm:
        if hasattr(eng, "disarm_next_session"):
            eng.disarm_next_session()
    else:
        mode = str(body.get("mode") or "standard")
        ttl = body.get("ttl_minutes")
        redact = body.get("redact_pii")
        if hasattr(eng, "arm_next_session"):
            eng.arm_next_session(mode=mode, ttl_minutes=ttl, redact_pii=redact)

    armed = eng.get_armed_state() if hasattr(eng, "get_armed_state") else None
    return {"ok": True, "armed": armed}


@router.post("/burn")
def burn_session(body: Dict[str, Any] = Body(default_factory=dict)) -> Any:
    eng = _resolve_engine()
    if eng is None:
        return {"ok": False, "error": "engine unavailable"}

    session_id = str(body.get("session_id") or "").strip()
    if not session_id:
        return {"ok": False, "error": "session_id required"}

    result = eng.burn_session(session_id, reason="desktop_burn")
    if not result["ok"]:
        return result
    return {"ok": True, "session_id": session_id, "receipt": result}


@router.post("/sweep")
def sweep_sessions() -> Any:
    eng = _resolve_engine()
    if eng is None:
        return {"ok": False, "error": "engine unavailable"}

    res = None
    if hasattr(eng, "sweep_expired"):
        res = eng.sweep_expired()
    return {"ok": True, "result": res}


@router.post("/verify")
def verify_session(body: Dict[str, Any] = Body(default_factory=dict)) -> Any:
    eng = _resolve_engine()
    if eng is None:
        return {"ok": False, "error": "engine unavailable"}

    session_id = str(body.get("session_id") or "").strip()
    if not session_id:
        return {"ok": False, "error": "session_id required"}

    res = None
    if hasattr(eng, "verify_zero_trace"):
        res = eng.verify_zero_trace(session_id)
    return {"ok": True, "session_id": session_id, "verification": res}
