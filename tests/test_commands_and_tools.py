import argparse
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_plugin_pkg():
    pkg_name = "hermes_plugin_incognito_test"
    if pkg_name in sys.modules:
        return sys.modules[pkg_name]
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        str(PROJECT_ROOT / "__init__.py"),
        submodule_search_locations=[str(PROJECT_ROOT)],
    )
    mod = importlib.util.module_from_spec(spec)
    mod.__path__ = [str(PROJECT_ROOT)]
    sys.modules[pkg_name] = mod
    spec.loader.exec_module(mod)
    return mod


plugin_init = _load_plugin_pkg()
from hermes_plugin_incognito_test.dashboard import plugin_api
from hermes_plugin_incognito_test.schemas import INCOGNITO_CONTROL_SCHEMA, INCOGNITO_VERIFY_SCHEMA
from hermes_plugin_incognito_test.tools import incognito_control, incognito_verify


class _RecordingCtx:
    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self.middleware = {}
        self.commands = {}
        self.cli = {}
        self.rpcs = {}
        self.events = []

    def register_tool(self, name, **kwargs):
        self.tools[name] = kwargs

    def register_hook(self, name, fn, **kwargs):
        self.hooks[name] = fn

    def register_middleware(self, kind, fn):
        self.middleware[kind] = fn

    def register_command(self, name, handler, **kwargs):
        self.commands[name] = handler

    def register_cli_command(self, name, setup_fn, handler_fn=None, **kwargs):
        self.cli[name] = (setup_fn, handler_fn)

    def register_rpc(self, name, fn):
        self.rpcs[name] = fn

    def register_skill(self, *args, **kwargs):
        pass

    def emit_to_session(self, session_id, event, payload=None):
        self.events.append((session_id, event, payload))
        return True


def test_tool_schemas_have_hermes_parameters_envelope():
    for schema in (INCOGNITO_CONTROL_SCHEMA, INCOGNITO_VERIFY_SCHEMA):
        assert "name" in schema
        assert "description" in schema
        assert isinstance(schema.get("parameters"), dict)
        assert schema["parameters"]["type"] == "object"
        assert "properties" in schema["parameters"]


def test_tools_dispatch_with_dict_args_and_kwargs(isolated_hermes_env):
    res_raw = incognito_control({"action": "enable", "mode": "strict", "ttl_minutes": 20}, conversation_id="sess-tool-1")
    res = json.loads(res_raw)
    assert res["ok"] is True
    assert res["mode"] == "strict"

    status = json.loads(incognito_control({"action": "status"}, conversation_id="sess-tool-1"))
    assert status["incognito"] is True
    assert status["mode"] == "strict"

    verified = json.loads(incognito_verify({"session_id": "sess-tool-1"}))
    assert verified["ok"] is True
    assert verified["zero_trace"] is False


def test_model_tool_cannot_burn_sweep_or_target_other_sessions():
    for sid in ("active", "other"):
        assert json.loads(incognito_control({"action": "enable"}, conversation_id=sid))["ok"]

    for payload in (
        {"action": "burn"}, {"action": "sweep"}, {"action": "off", "keep": False},
        {"action": "disable", "disable_action": "burn"},
    ):
        payload["session_id"] = "other"
        assert not json.loads(incognito_control(payload, conversation_id="active"))["ok"]

    disabled = json.loads(incognito_control(
        {"action": "disable", "session_id": "other"}, conversation_id="active"
    ))
    assert disabled["ok"]
    assert disabled["session_id"] == "active"
    assert not json.loads(incognito_control({"action": "disable"}, conversation_id="active"))["ok"]
    assert json.loads(incognito_control({"action": "status"}, conversation_id="other"))["incognito"]


def test_incognito_control_burn_and_disable_only_target_active_incognito_and_block_model_burns(isolated_hermes_env):
    """
    Model-facing incognito_control must:
      1) Omit session_id from INCOGNITO_CONTROL_SCHEMA and ignore payload['session_id'] on burn/disable.
      2) Refuse burn and disable unless engine.is_incognito(active_sid) is True.
      3) Block model-started burns (action='burn' or disable with burn) in pre_tool_call.
         Ported from upstream main, where these were routed to 'approve'. This PR reserves
         deletion for user-facing controls, so the guard blocks them instead.
    """
    assert "session_id" not in INCOGNITO_CONTROL_SCHEMA["parameters"]["properties"]

    ctx = _RecordingCtx()
    plugin_init.register(ctx)
    pre_tool = ctx.hooks["pre_tool_call"]

    # Victim incognito session exists on host, while caller is a different non-incognito session
    incognito_control({"action": "enable", "mode": "strict"}, conversation_id="sess-victim-incog")

    # Attempt cross-session burn via payload['session_id'] from non-incognito caller -> refused & victim intact
    cross_burn = json.loads(
        incognito_control(
            {"action": "burn", "session_id": "sess-victim-incog"},
            conversation_id="sess-normal-caller",
        )
    )
    assert cross_burn["ok"] is False
    cross_disable = json.loads(
        incognito_control(
            {"action": "disable", "disable_action": "burn", "session_id": "sess-victim-incog"},
            conversation_id="sess-normal-caller",
        )
    )
    assert cross_disable["ok"] is False

    victim_status = json.loads(incognito_control({"action": "status"}, conversation_id="sess-victim-incog"))
    assert victim_status["incognito"] is True

    # pre_tool_call blocks model-started burn from non-incognito session
    guard_non_incog = pre_tool("incognito_control", {"action": "burn"}, session_id="sess-normal-caller")
    assert guard_non_incog is not None
    assert guard_non_incog["action"] == "block"

    # pre_tool_call blocks model-started burns even on the active incognito session
    guard_incog_burn = pre_tool("incognito_control", {"action": "burn"}, session_id="sess-victim-incog")
    assert guard_incog_burn is not None
    assert guard_incog_burn["action"] == "block"

    guard_incog_disable_burn = pre_tool(
        "incognito_control",
        {"action": "disable", "keep": False},
        session_id="sess-victim-incog",
    )
    assert guard_incog_disable_burn is not None
    assert guard_incog_disable_burn["action"] == "block"

    guard_wrapped_burn = pre_tool(
        "tool_call",
        {"calls": [{"name": "incognito_control", "arguments": {"action": "burn"}}]},
        session_id="sess-victim-incog",
    )
    assert guard_wrapped_burn is not None
    assert guard_wrapped_burn["action"] == "block"


def test_slash_cli_rpc_and_rest_api_end_to_end(isolated_hermes_env, capsys):
    ctx = _RecordingCtx()
    plugin_init.register(ctx)

    slash = ctx.commands["incognito"]
    msg_on = slash("on strict 25", session_id="sess-slash-1")
    assert "enabled" in msg_on.lower()
    assert any(ev[0] == "sess-slash-1" and ev[1] == "state.changed" for ev in ctx.events)

    msg_ttl = slash("ttl 10", session_id="sess-slash-1")
    assert "10 minutes" in msg_ttl

    msg_status = slash("status", session_id="sess-slash-1")
    assert "strict" in msg_status.lower()

    msg_burn = slash("burn", session_id="sess-slash-1")
    assert "burned" in msg_burn.lower()

    msg_verify = slash("verify sess-slash-1", session_id="")
    assert "no tracked local artifacts found" in msg_verify.lower()

    # Test RPC methods
    rpc_arm_res = ctx.rpcs["arm"]({"mode": "strict", "ttl_minutes": 15, "redact_pii": True})
    assert rpc_arm_res["ok"] is True
    assert rpc_arm_res["armed"]["mode"] == "strict"

    # Simulate session start hook consuming the armed state
    ctx.hooks["on_session_start"](session_id="sess-armed-1")
    rpc_status_res = ctx.rpcs["status"]({"session_id": "sess-armed-1"})
    assert rpc_status_res["incognito"] is True
    assert rpc_status_res["mode"] == "strict"

    # Switch mode in place via REST API /toggle
    toggled = plugin_api.toggle_session({"session_id": "sess-armed-1", "mode": "standard"})
    assert toggled["incognito"] is True
    assert toggled["mode"] == "standard"

    # Per-turn on_session_end keeps multi-turn incognito session alive; on_session_finalize purges on close
    ctx.hooks["on_session_end"](session_id="sess-armed-1")
    assert plugin_api.get_status("sess-armed-1")["incognito"] is True

    ctx.hooks["on_session_finalize"](session_id="sess-armed-1")
    verify_api = plugin_api.verify_session({"session_id": "sess-armed-1"})
    assert verify_api["verification"]["zero_trace"] is True

    # Test CLI subcommands
    setup_fn, handler_fn = ctx.cli["incognito"]
    parser = argparse.ArgumentParser()
    setup_fn(parser)
    ns = parser.parse_args(["status", "--json"])
    assert handler_fn(ns) == 0
    captured = json.loads(capsys.readouterr().out)
    assert captured["ok"] is True
