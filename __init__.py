"""Hermes Incognito Plugin.

Ephemeral and incognito sessions for Hermes CLI, TUI, Gateway, and Desktop.
Hides active chats from listings, blocks persistent memory mutations, strips profile
memory in strict mode, optionally redacts outbound PII in RAM, and scrubs SQLite
compression chains and transcript artifacts on close or TTL expiry.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional

try:
    from gateway.session_context import get_session_env
except ImportError:
    def get_session_env(name: str = "", default: str = "") -> str:
        return default

try:
    from .engine import IncognitoActivationError, get_engine
    from .schemas import INCOGNITO_CONTROL_SCHEMA, INCOGNITO_VERIFY_SCHEMA
    from .tools import incognito_control, incognito_verify
except (ImportError, ValueError):
    from engine import IncognitoActivationError, get_engine
    from schemas import INCOGNITO_CONTROL_SCHEMA, INCOGNITO_VERIFY_SCHEMA
    from tools import incognito_control, incognito_verify

logger = logging.getLogger(__name__)

MASKING_BLOCKED_MESSAGE = (
    "Incognito didn't send this message because it couldn't mask your personal details. "
    "Try again, or turn off Mask personal details."
)


def _blocked_response(message: str) -> SimpleNamespace:
    """Return a local reply from execution middleware without calling the provider."""
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(role="assistant", content=message, tool_calls=None),
            finish_reason="stop",
        )],
        content=[SimpleNamespace(type="text", text=message)],
        stop_reason="end_turn",
        status="completed",
        output=[SimpleNamespace(
            type="message", role="assistant", status="completed",
            content=[SimpleNamespace(type="output_text", text=message)],
        )],
        usage=None,
    )


def _resolve_session_id(kwargs: dict[str, Any], explicit: str = "") -> str:
    """Resolve session ID from argument, kwargs, or gateway context."""
    if explicit:
        return explicit
    sid = str(kwargs.get("session_id") or kwargs.get("conversation_id") or kwargs.get("task_id") or "")
    if not sid:
        try:
            sid = str(get_session_env("HERMES_SESSION_ID") or get_session_env("HERMES_SESSION_KEY") or "")
        except Exception:
            pass
    return sid


def register(ctx: Any) -> None:
    """Entry point called by Hermes plugin loader to register capabilities."""
    engine = get_engine()
    emit_to_session = getattr(ctx, "emit_to_session", None)
    if callable(emit_to_session):
        def notify_burned(session_id: str) -> None:
            emit_to_session(session_id, "state.changed", {
                "session_id": session_id, "active": False, "burned": True
            })

        engine.on_burn_complete = notify_burned

    # -------------------------------------------------------------------------
    # 1. Register Tools
    # -------------------------------------------------------------------------
    ctx.register_tool(
        name="incognito_control",
        toolset="incognito",
        schema=INCOGNITO_CONTROL_SCHEMA,
        handler=incognito_control,
        description="Manage active incognito session status, mode, arming, and TTL",
    )
    ctx.register_tool(
        name="incognito_verify",
        toolset="incognito",
        schema=INCOGNITO_VERIFY_SCHEMA,
        handler=incognito_verify,
        description="Verify zero trace in SQLite, disk files, and RAM for a session",
    )

    # -------------------------------------------------------------------------
    # 2. Register Hooks
    # -------------------------------------------------------------------------
    def on_session_start(session_id: str = "", **kwargs: Any) -> None:
        """Initialize session state and sweep expired orphans."""
        sid = _resolve_session_id(kwargs, session_id)
        if sid:
            try:
                engine.consume_armed_session(sid)
            except IncognitoActivationError:
                logger.warning("Could not activate Incognito at session start; the first turn will retry.")
        engine.sweep_expired()

    def pre_llm_call(session_id: str = "", is_first_turn: bool = False, **kwargs: Any) -> Any:
        """Activate an armed session, mask this turn's messages, and return a context reminder.

        Runs before Hermes titles the chat, compacts it, prefetches memory, or stores the turn, so
        masking the message dicts here keeps original values out of those paths. A masking failure
        vetoes the turn (no model call at all).
        """
        sid = _resolve_session_id(kwargs, session_id)
        if not sid:
            return None
        try:
            if is_first_turn:
                engine.consume_armed_session(sid)
            if engine.masking_active(sid):
                engine.mask_messages_in_place(sid, kwargs.get("conversation_history"))
        except IncognitoActivationError as exc:
            return {"action": "block", "message": f"Could not activate Incognito. {exc}"}
        except Exception as exc:
            logger.warning("Incognito could not mask this turn (%s); blocking it.", type(exc).__name__)
            return {"action": "block", "message": MASKING_BLOCKED_MESSAGE}
        if engine.is_incognito(sid):
            engine.touch_session(sid)
            if is_first_turn:
                return "[Incognito session active: do not attempt persistent memory or skill writes.]"
        return None

    def pre_tool_call(
        tool_name: str = "", args: Optional[dict[str, Any]] = None, session_id: str = "", **kwargs: Any
    ) -> Optional[dict[str, str]]:
        """Guard against persistent state mutations and cross-session incognito reads."""
        sid = _resolve_session_id(kwargs, session_id)
        return engine.evaluate_tool_guard(sid, tool_name, args)

    def transform_tool_result(
        tool_name: str = "",
        args: Optional[dict[str, Any]] = None,
        result: Any = None,
        session_id: str = "",
        **kwargs: Any,
    ) -> Optional[str]:
        """Scrub protected sessions from search results, then mask personal details in the result.

        Runs before the result joins the conversation, so the stored history and any later
        compaction summary only ever see the masked text.
        """
        sid = _resolve_session_id(kwargs, session_id)
        scrubbed = engine.scrub_tool_result(sid, tool_name, args, result)
        current = scrubbed if scrubbed is not None else result
        try:
            masked = engine.mask_tool_result(sid, current)
        except Exception as exc:
            logger.warning("Incognito could not mask a tool result (%s); withholding it.", type(exc).__name__)
            return "[tool result withheld: Incognito couldn't mask personal details in it]"
        return masked if masked is not None else scrubbed

    def subagent_start(parent_session_id: str = "", child_session_id: Any = None, **kwargs: Any) -> None:
        """A helper agent started from an Incognito chat inherits its protection and masking."""
        if parent_session_id and child_session_id:
            engine.adopt_subagent(str(parent_session_id), str(child_session_id))

    def post_compaction(old_session_id: str = "", session_id: str = "", **kwargs: Any) -> None:
        """Propagate incognito protection and in-RAM vaults to compacted sessions."""
        new_sid = session_id or str(kwargs.get("new_session_id") or "")
        if old_session_id and new_sid:
            engine.propagate_compaction(old_session_id, new_sid)

    def on_session_end(session_id: str = "", **kwargs: Any) -> None:
        """Refresh lease and keep session hidden at the end of each conversation turn."""
        sid = _resolve_session_id(kwargs, session_id)
        if not sid or not engine.is_incognito(sid):
            return
        engine.touch_session(sid)
        engine.ensure_hidden_in_db(sid)

    def on_session_cleanup(session_id: str = "", **kwargs: Any) -> None:
        """Auto-purge incognito sessions when finalized or reset."""
        sid = _resolve_session_id(kwargs, session_id)
        if not sid:
            return
        engine.end_save_undo(sid)
        if engine.is_incognito(sid) and engine.get_settings().get("auto_purge_on_exit", True):
            if engine.live_head_for(sid):
                # A compacted ancestor ends while its conversation continues in a live head.
                # It is deleted when that head is burned, never on its own.
                return
            reason = str(kwargs.get("hook_name") or "session_finalize")
            result = engine.burn_session(sid, reason=reason)
            if result.get("ok") and result["pending_burn"] and callable(emit_to_session):
                try:
                    emit_to_session(sid, "state.changed", {"session_id": sid, "active": True, "burned": False})
                except Exception:
                    pass

    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    ctx.register_hook("post_compaction", post_compaction)
    ctx.register_hook("subagent_start", subagent_start)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("on_session_finalize", on_session_cleanup)
    ctx.register_hook("on_session_reset", on_session_cleanup)

    # -------------------------------------------------------------------------
    # 3. Register Middleware
    # -------------------------------------------------------------------------
    def on_llm_request(request: dict[str, Any], session_id: str = "", **kwargs: Any) -> Optional[dict[str, Any]]:
        """Sanitize LLM requests with strict memory stripping and PII masking. Never raises."""
        sid = _resolve_session_id(kwargs, session_id)
        try:
            return engine.transform_llm_request(sid, request)
        except Exception as exc:
            # Hermes would skip a raising middleware and send the request as-is; the execution
            # gate below re-masks and re-checks the payload, so this request still can't leak.
            logger.warning("Incognito request middleware failed (%s).", type(exc).__name__)
            return None

    def on_llm_execution(
        request: dict[str, Any], next_call: Callable[[dict[str, Any]], Any], session_id: str = "", **kwargs: Any
    ) -> Any:
        """Last gate before the provider: mask, re-check, and refuse to send on any doubt.

        Model replies are passed through unchanged; placeholders are never swapped back.
        """
        sid = _resolve_session_id(kwargs, session_id)
        try:
            payload, problem = engine.guard_outbound(sid, request)
        except Exception as exc:
            logger.warning("Incognito masking gate failed (%s); blocking the send.", type(exc).__name__)
            payload, problem = None, MASKING_BLOCKED_MESSAGE
        if problem:
            return _blocked_response(problem)
        return next_call(payload if payload is not None else request)

    ctx.register_middleware("llm_request", on_llm_request)
    ctx.register_middleware("llm_execution", on_llm_execution)

    # -------------------------------------------------------------------------
    # 4. Register Slash Command (/incognito)
    # -------------------------------------------------------------------------
    def handle_slash_command(
        raw_args: str = "",
        *,
        session_id: str = "",
        platform: str = "",
        source: Any = None,
        **kwargs: Any,
    ) -> str:
        """Handle in-session /incognito slash command invocations."""
        sid = _resolve_session_id(kwargs, session_id)
        parts = raw_args.strip().split()
        subcmd = parts[0].lower() if parts else ""

        def _emit_state() -> None:
            if hasattr(ctx, "emit_to_session") and sid:
                try:
                    state = engine.get_session_state(sid)
                    ctx.emit_to_session(sid, "state.changed", state)
                except Exception:
                    pass

        if subcmd == "toggle":
            if sid:
                res = engine.toggle_session(sid)
                if not res["ok"]:
                    return res["error"]
                _emit_state()
                if res.get("mode") != "off":
                    return f"Incognito mode enabled ({res.get('mode')}) for session {sid}."
                return f"Incognito mode disabled for session {sid}. History retained."
            if engine.get_armed_state():
                engine.disarm_next_session()
                return "Disarmed pending next-session token."
            engine.arm_next_session()
            return "Next session armed for incognito (standard mode)."

        if not subcmd or subcmd == "status":
            summary = engine.status_summary(session_id=sid)
            curr = summary.get("current_session")
            if curr and curr.get("pending_burn"):
                return "Burn pending. Incognito protections are active while Hermes retries cleanup."
            if curr and curr.get("active"):
                rem = (curr.get("remaining_seconds") or 0) // 60
                return (
                    f"Incognito Active ({curr.get('mode')})\n"
                    f"• Remaining TTL: {rem}m\n"
                    f"• Blocked Writes: {curr.get('blocked_writes', 0)}\n"
                    f"• PII Redactions: {curr.get('redactions', 0)}"
                )
            armed = summary.get("armed")
            armed_str = f"Armed ({armed['mode']})" if armed else "None"
            return f"Incognito Inactive. Next session: {armed_str}. Active incognito sessions: {summary.get('active_count', 0)}."

        if subcmd in ("on", "enable"):
            mode = "strict" if len(parts) > 1 and parts[1].lower() == "strict" else "standard"
            ttl = None
            if len(parts) > 2 and parts[2].isdigit():
                ttl = int(parts[2])
            elif len(parts) > 1 and parts[1].isdigit():
                ttl = int(parts[1])

            if sid:
                res = engine.enable_session(sid, mode=mode, ttl_minutes=ttl)
                if not res["ok"]:
                    return res["error"]
                _emit_state()
                return f"Incognito mode enabled ({mode}) for session {sid}."
            engine.arm_next_session(mode=mode, ttl_minutes=ttl)
            return f"Next session armed for incognito ({mode} mode)."

        if subcmd == "strict":
            ttl = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            if sid:
                res = engine.enable_session(sid, mode="strict", ttl_minutes=ttl)
                if not res["ok"]:
                    return res["error"]
                _emit_state()
                return f"Strict clean-room incognito mode enabled for session {sid}."
            engine.arm_next_session(mode="strict", ttl_minutes=ttl)
            return "Next session armed for strict incognito mode."

        if subcmd == "burn" or (
            subcmd in ("off", "disable") and len(parts) > 1 and parts[1].lower() == "burn"
        ):
            if not sid:
                return "No active session ID to burn."
            res = engine.burn_session(sid, reason="slash_burn")
            if not res["ok"]:
                return f"Burn refused: {res['error']}"
            _emit_state()
            if res["pending_burn"]:
                return f"Burn pending for session {sid}. Hermes will retry cleanup."
            return f"Incognito session {sid} burned. Files scrubbed: {res['files_scrubbed']}. (Receipt: {res['receipt_id']})"

        if subcmd in ("off", "disable"):
            if sid:
                res = engine.disable_session(sid)
                if not res["ok"]:
                    return res["error"]
                _emit_state()
                return f"Incognito mode disabled for session {sid}. History retained."
            engine.disarm_next_session()
            return "Disarmed pending next-session token."

        if subcmd == "save":
            if not sid:
                return "No active session to save."
            if not engine.is_incognito(sid):
                return "This chat isn't in Incognito, so it's already saved."
            if len(parts) < 2 or parts[1].lower() not in ("confirm", "yes"):
                state = engine.get_session_state(sid) or {}
                masked = (
                    " Personal details stay masked in the saved messages; the real values aren't added back."
                    if state.get("redact_pii") else ""
                )
                return (
                    "Save this chat? It moves to your chat history and won't be deleted automatically."
                    f"{masked} You can undo this for {engine.get_settings().get('save_undo_minutes', 10)} minutes "
                    "or until you close the chat.\nRun /incognito save confirm to save it."
                )
            res = engine.save_session(sid)
            if not res.get("ok"):
                return str(res.get("error"))
            _emit_state()
            return (
                f"Chat saved to your history. Run /incognito undo within {res['undo_seconds'] // 60} minutes "
                "to bring it back to Incognito."
            )

        if subcmd == "undo":
            if not sid:
                return "No active session."
            res = engine.undo_save(sid)
            if not res.get("ok"):
                return str(res.get("error"))
            _emit_state()
            return f"Back in Incognito ({res['mode']}). This chat will be deleted when you're done."

        if subcmd == "mask":
            if not sid or not engine.is_incognito(sid):
                return "Turn on Incognito first: /incognito on"
            want = (parts[1].lower() if len(parts) > 1 else "on") not in ("off", "no", "false")
            state = engine.get_session_state(sid) or {}
            res = engine.enable_session(sid, mode=state.get("mode", "standard"), redact_pii=want)
            if not res.get("ok"):
                return str(res.get("error"))
            _emit_state()
            return "Personal details will be masked before anything is sent." if want else "Masking is off for this chat."

        if subcmd == "arm":
            mode = "strict" if len(parts) > 1 and parts[1].lower() == "strict" else "standard"
            ttl = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
            engine.arm_next_session(mode=mode, ttl_minutes=ttl)
            return f"Next session armed for incognito ({mode} mode)."

        if subcmd == "disarm":
            engine.disarm_next_session()
            return "Armed next-session token cleared."

        if subcmd == "sweep":
            res = engine.sweep_expired()
            return f"Swept {res.get('swept_count', 0)} expired/orphaned sessions. {res.get('active_remaining', 0)} active remaining."

        if subcmd == "ttl":
            if not sid:
                return "No active session ID."
            if len(parts) < 2 or not parts[1].isdigit():
                return "Usage: /incognito ttl <minutes>"
            ttl_val = int(parts[1])
            ttl_res = engine.set_session_ttl(sid, ttl_val)
            if not ttl_res.get("ok"):
                return str(ttl_res.get("error") or f"Session {sid} is not currently incognito.")
            _emit_state()
            return f"Inactivity TTL set to {ttl_val} minutes for session {sid}."

        if subcmd == "verify":
            target_id = parts[1] if len(parts) > 1 else sid
            if not target_id:
                return "Usage: /incognito verify <session_id>"
            res = engine.verify_zero_trace(target_id)
            if res.get("zero_trace"):
                return f"No tracked local artifacts found for {target_id}."
            return (
                f"Local cleanup check for {target_id}: "
                f"DB rows={res.get('db_rows_found')}, "
                f"Files={res.get('session_files_found')}, "
                f"RAM={res.get('ram_vault_entries')}."
            )

        return (
            "Usage: /incognito [status|on|off|toggle|strict|mask [on|off]|save|undo|burn|sweep|ttl <min>|arm|verify <id>]\n"
            "Manage privacy and cleanup for ephemeral chats."
        )

    ctx.register_command(
        name="incognito",
        handler=handle_slash_command,
        description="Show or manage Incognito mode for this session",
        args_hint="[status|on|strict|off|toggle|mask|save|undo|burn|sweep|ttl <min>|arm|verify <id>]",
    )

    # Register direct subcommand aliases so TUI/CLI/Desktop '/' autocomplete popup
    # displays all incognito suboptions immediately when typing '/incognito'.
    _slash_suboptions = (
        ("incognito-strict", "strict", "Enable strict clean-room incognito mode (strips profile & memory)"),
        ("incognito-on", "on standard", "Enable standard ephemeral incognito mode for this session"),
        ("incognito-off", "off", "Disable incognito mode and retain conversation history"),
        ("incognito-burn", "burn", "Immediately scrub, zero-fill, and delete this session"),
        ("incognito-save", "save", "Keep this chat: move it to normal history (asks first, can be undone)"),
        ("incognito-undo", "undo", "Bring a just-saved chat back to Incognito"),
        ("incognito-mask", "mask", "Mask personal details before anything is sent to the model"),
        ("incognito-status", "status", "Show active incognito mode, TTL, and blocked writes"),
        ("incognito-arm", "arm", "Arm the next new session to start in incognito mode"),
        ("incognito-sweep", "sweep", "Purge expired or orphaned incognito sessions"),
        ("incognito-verify", "verify", "Audit SQLite, disk, and RAM for zero residual trace"),
    )
    for alias_name, preset_prefix, alias_desc in _slash_suboptions:
        def _make_alias_handler(prefix: str) -> Callable[..., str]:
            def _alias_handler(raw_args: str = "", **kw: Any) -> str:
                merged = f"{prefix} {raw_args}".strip() if raw_args.strip() else prefix
                return handle_slash_command(merged, **kw)
            return _alias_handler

        ctx.register_command(
            name=alias_name,
            handler=_make_alias_handler(preset_prefix),
            description=alias_desc,
        )

    # -------------------------------------------------------------------------
    # 5. Register CLI Subcommand (hermes incognito ...)
    # -------------------------------------------------------------------------
    def setup_incognito_cli(subparser: argparse.ArgumentParser) -> None:
        """Setup CLI argument parser tree for hermes incognito."""
        subs = subparser.add_subparsers(dest="incognito_cmd")

        # status
        p_status = subs.add_parser("status", help="Show incognito status and audit metrics")
        p_status.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        # arm
        p_arm = subs.add_parser("arm", help="Arm next session for incognito mode")
        p_arm.add_argument("--mode", choices=["standard", "strict"], default="standard", help="Incognito mode")
        p_arm.add_argument("--ttl", type=int, default=None, help="TTL in minutes")
        p_arm.add_argument("--redact-pii", action="store_true", help="Redact outbound PII in RAM")
        p_arm.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        # disarm
        p_disarm = subs.add_parser("disarm", help="Disarm pending next session")
        p_disarm.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        # sweep
        p_sweep = subs.add_parser("sweep", help="Sweep expired or dead incognito sessions")
        p_sweep.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        # burn
        p_burn = subs.add_parser("burn", help="Burn and zero-scrub an incognito session")
        p_burn.add_argument("session_id", help="Session ID to burn")
        p_burn.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        # save / undo
        p_save = subs.add_parser("save", help="Keep an incognito chat in normal history (can be undone)")
        p_save.add_argument("session_id", help="Session ID to save")
        p_save.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
        p_save.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")
        p_undo = subs.add_parser("undo", help="Bring a just-saved chat back to incognito")
        p_undo.add_argument("session_id", help="Session ID to return to incognito")
        p_undo.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        # verify
        p_verify = subs.add_parser("verify", help="Verify zero residual trace for a session")
        p_verify.add_argument("session_id", help="Session ID to verify")
        p_verify.add_argument("--json", action="store_true", dest="as_json", help="Output JSON format")

        subparser.set_defaults(func=handle_incognito_cli)

    def handle_incognito_cli(args: argparse.Namespace) -> int:
        """Execute CLI subcommands for hermes incognito."""
        cmd = getattr(args, "incognito_cmd", None)
        as_json = getattr(args, "as_json", False)

        if not cmd or cmd == "status":
            summary = engine.status_summary()
            if as_json:
                print(json.dumps(summary, indent=2))
            else:
                audit = summary.get("audit", {})
                armed = summary.get("armed")
                settings = summary.get("settings", {})
                armed_text = f"{armed['mode']} (TTL: {armed['ttl_minutes']}m)" if armed else "None"
                print("=" * 50)
                print("           HERMES INCOGNITO STATUS")
                print("=" * 50)
                print(f"Active Incognito Sessions: {summary.get('active_count', 0)}")
                print(f"Pending Next-Session Arm : {armed_text}")
                print(f"Default Mode Configured  : {settings.get('default_mode', 'off')}")
                print(f"Auto-Purge On Exit       : {settings.get('auto_purge_on_exit', True)}")
                print(f"Redact Outbound PII      : {settings.get('redact_outbound_pii', False)}")
                print(f"Zero-Fill Files On Burn  : {settings.get('zero_fill_files', True)}")
                print("\nAudit Totals:")
                print(f"  Sessions Protected     : {audit.get('sessions_protected', 0)}")
                print(f"  Sessions Burned        : {audit.get('sessions_burned', 0)}")
                print(f"  Orphans Swept          : {audit.get('orphans_swept', 0)}")
                print(f"  Writes Blocked         : {audit.get('writes_blocked', 0)}")
                print(f"  PII Redactions         : {audit.get('pii_redactions', 0)}")
                print(f"  Files Scrubbed         : {audit.get('files_scrubbed', 0)}")
                print("=" * 50)
            return 0

        elif cmd == "arm":
            res = engine.arm_next_session(
                mode=getattr(args, "mode", "standard"),
                ttl_minutes=getattr(args, "ttl", None),
                redact_pii=getattr(args, "redact_pii", None),
            )
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                armed = res.get("armed", {})
                print(
                    f"✓ Next session armed for incognito (mode: {armed.get('mode')}, "
                    f"TTL: {armed.get('ttl_minutes')}m, Redact PII: {armed.get('redact_pii')})"
                )
            return 0

        elif cmd == "disarm":
            res = engine.disarm_next_session()
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                print("✓ Pending next-session incognito token cleared.")
            return 0

        elif cmd == "sweep":
            res = engine.sweep_expired()
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                print(
                    f"✓ Swept {res.get('swept_count', 0)} expired/orphaned sessions. "
                    f"{res.get('active_remaining', 0)} active incognito sessions remaining."
                )
            return 0

        elif cmd == "burn":
            target_sid = getattr(args, "session_id", "")
            if not target_sid:
                print("Error: session_id is required for burn")
                return 1
            res = engine.burn_session(target_sid, reason="cli_burn")
            if as_json:
                print(json.dumps(res, indent=2))
            elif not res["ok"]:
                print(f"Burn refused: {res['error']}")
            elif res["pending_burn"]:
                print(f"Burn pending for session {target_sid}. Hermes will retry cleanup.")
            else:
                print(
                    f"✓ Burned session {target_sid}: DB deleted={res.get('db_deleted')}, "
                    f"Files scrubbed={res.get('files_scrubbed')}, "
                    f"Vault cleared={res.get('vault_keys_cleared')} (Receipt: {res.get('receipt_id')})"
                )
            return 0 if res["ok"] else 1

        elif cmd == "save":
            target_sid = getattr(args, "session_id", "")
            if not getattr(args, "yes", False):
                print(
                    "Saving moves this chat to your history and stops its auto-delete timer. "
                    "Masked details stay masked. You can undo it for a few minutes."
                )
                try:
                    answer = input("Save this chat? [y/N] ").strip().lower()
                except EOFError:
                    answer = ""
                if answer not in ("y", "yes"):
                    print("Not saved.")
                    return 1
            res = engine.save_session(target_sid)
            if as_json:
                print(json.dumps(res, indent=2))
            elif res.get("ok"):
                print(f"✓ Saved {target_sid}. Undo with: hermes incognito undo {target_sid}")
            else:
                print(f"Not saved: {res.get('error')}")
            return 0 if res.get("ok") else 1

        elif cmd == "undo":
            target_sid = getattr(args, "session_id", "")
            res = engine.undo_save(target_sid)
            if as_json:
                print(json.dumps(res, indent=2))
            elif res.get("ok"):
                print(f"✓ {target_sid} is back in incognito ({res.get('mode')}).")
            else:
                print(f"Undo failed: {res.get('error')}")
            return 0 if res.get("ok") else 1

        elif cmd == "verify":
            target_sid = getattr(args, "session_id", "")
            if not target_sid:
                print("Error: session_id is required for verify")
                return 1
            res = engine.verify_zero_trace(target_sid)
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                if res.get("zero_trace"):
                    print(f"✓ No tracked local artifacts found for {target_sid}.")
                else:
                    print(
                        f"✗ Local cleanup check for {target_sid}: "
                        f"DB rows={res.get('db_rows_found')}, "
                        f"Session files={res.get('session_files_found')}, "
                        f"Hook files={res.get('hook_files_found')}, "
                        f"RAM entries={res.get('ram_vault_entries')}, "
                        f"Active lease={res.get('active_lease')}"
                    )
            return 0 if res.get("zero_trace") else 1

        return 0

    if hasattr(ctx, "register_cli_command"):
        ctx.register_cli_command(
            name="incognito",
            help="Manage Incognito sessions and local cleanup",
            setup_fn=setup_incognito_cli,
            handler_fn=handle_incognito_cli,
            description="Operator CLI for Hermes Incognito plugin.",
        )
    elif hasattr(ctx, "register_cli"):
        ctx.register_cli(
            name="incognito",
            handler=handle_incognito_cli,
            setup_fn=setup_incognito_cli,
        )

    # -------------------------------------------------------------------------
    # 6. Register RPC Methods
    # -------------------------------------------------------------------------
    if hasattr(ctx, "register_rpc"):
        def rpc_status(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            sid = (params or {}).get("session_id") or session_id
            return engine.status_summary(sid)

        def rpc_toggle(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            p = params or {}
            sid = str(p.get("session_id") or session_id or "").strip()
            mode = str(p.get("mode") or "standard")
            ttl = p.get("ttl_minutes")
            redact = p.get("redact_pii")
            if sid and sid != "new":
                result = engine.toggle_session(sid, mode=mode, ttl_minutes=ttl, redact_pii=redact)
                return engine.status_summary(sid) if result["ok"] else result
            if mode == "off" or engine.get_armed_state():
                engine.disarm_next_session()
            else:
                engine.arm_next_session(mode=mode, ttl_minutes=ttl, redact_pii=redact)
            return engine.status_summary("")

        def rpc_enable(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            p = params or {}
            sid = str(p.get("session_id") or session_id or "").strip()
            mode = str(p.get("mode") or "standard").strip().lower()
            if not sid:
                return {"ok": False, "error": "session_id required"}
            if mode not in ("standard", "strict"):
                return {"ok": False, "error": "mode must be 'standard' or 'strict'"}
            ttl = p.get("ttl_minutes")
            redact = p.get("redact_pii")
            result = engine.enable_session(
                sid, mode=mode, ttl_minutes=int(ttl) if ttl is not None else None,
                redact_pii=None if redact is None else bool(redact),
            )
            return {**engine.status_summary(sid), "ok": True} if result.get("ok") else result

        def rpc_disable(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            sid = str((params or {}).get("session_id") or session_id or "").strip()
            if not sid or not engine.is_incognito(sid):
                return {"ok": False, "error": "This chat is not in Incognito."}
            result = engine.disable_session(sid, action="keep")
            return {**engine.status_summary(sid), "ok": True} if result.get("ok") else result

        def rpc_save(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            sid = str((params or {}).get("session_id") or session_id or "").strip()
            result = engine.save_session(sid)
            return {**engine.status_summary(sid), **result} if result.get("ok") else result

        def rpc_undo(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            sid = str((params or {}).get("session_id") or session_id or "").strip()
            result = engine.undo_save(sid)
            return {**engine.status_summary(sid), **result} if result.get("ok") else result

        def rpc_arm(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            p = params or {}
            if p.get("disarm"):
                return engine.disarm_next_session()
            mode = p.get("mode", "standard")
            ttl = p.get("ttl_minutes")
            redact = p.get("redact_pii")
            return engine.arm_next_session(mode=mode, ttl_minutes=ttl, redact_pii=redact)

        def rpc_burn(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            p = params or {}
            sid = p.get("session_id") or session_id
            return engine.burn_session(sid, reason="rpc_burn")

        def rpc_sweep(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            return engine.sweep_expired()

        def rpc_verify(params: Optional[dict[str, Any]] = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
            p = params or {}
            sid = p.get("session_id") or session_id
            res = engine.verify_zero_trace(sid)
            return {"ok": True, "session_id": sid, "verification": res, **res}

        try:
            ctx.register_rpc("status", rpc_status)
            ctx.register_rpc("toggle", rpc_toggle)
            ctx.register_rpc("enable", rpc_enable)
            ctx.register_rpc("save", rpc_save)
            ctx.register_rpc("undo", rpc_undo)
            ctx.register_rpc("disable", rpc_disable)
            ctx.register_rpc("arm", rpc_arm)
            ctx.register_rpc("burn", rpc_burn)
            ctx.register_rpc("sweep", rpc_sweep)
            ctx.register_rpc("verify", rpc_verify)
        except Exception as exc:
            logger.debug("Failed to register RPC methods: %s", exc)

    # -------------------------------------------------------------------------
    # 7. Register Bundled Skill
    # -------------------------------------------------------------------------
    skill_md = Path(__file__).resolve().parent / "skills" / "incognito-privacy" / "SKILL.md"
    if skill_md.is_file() and hasattr(ctx, "register_skill"):
        try:
            ctx.register_skill(
                name="incognito-privacy",
                path=skill_md,
                description="Incognito session commands, tools, and privacy patterns",
            )
        except Exception as exc:
            logger.debug("Failed to register incognito skill: %s", exc)
