"""End-to-end and canary tests: with "Mask personal details" on, no raw value may leave the machine
or be written anywhere, on any path the plugin can reach. See tests/hermes_sim.py for the host model."""

from __future__ import annotations

import json
import logging
import random
import string

import pytest
from hermes_sim import (
    SimHermes,
    install_fake_hermes_middleware,
    load_plugin,
    scan_files,
)

plugin = load_plugin()
from hermes_plugin_incognito_test import engine as plugin_engine
from hermes_plugin_incognito_test.dashboard import plugin_api

CANARIES = {
    "email": "canary.leak.7731@example.org",
    "phone": "+57 311 555 0199",
    "card": "4111 1111 1111 1111",
    "iban": "DE89370400440532013000",
    "ssn": "078-05-1120",
    "cedula": "1.020.304.050",
    "ip": "203.0.113.77",
    "secret": "sk-proj-CANARYabcdefghijklmnop12345",
    "password": "Tigre#Canary2024",
    "address": "Calle 45 # 12-34",
}
USER_TEXT = (
    f"Hi, I'm reachable at {CANARIES['email']} or {CANARIES['phone']}. My card is {CANARIES['card']}, "
    f"IBAN {CANARIES['iban']}, SSN {CANARIES['ssn']}, cédula {CANARIES['cedula']}. Server {CANARIES['ip']}, "
    f"key {CANARIES['secret']}, password: {CANARIES['password']}. I live at {CANARIES['address']}."
)
TOOL_OUTPUT = (
    f"notes.txt:\ncontact={CANARIES['email']}\nphone {CANARIES['phone']}\ncard {CANARIES['card']}\n"
    f"api_key = {CANARIES['secret']}\nhost {CANARIES['ip']}"
)
API_MODES = ["chat_completions", "codex_responses", "anthropic_messages"]


@pytest.fixture
def sim_factory(isolated_hermes_env, monkeypatch):
    install_fake_hermes_middleware(monkeypatch)

    def make(**kwargs):
        return SimHermes(plugin, isolated_hermes_env["home"], **kwargs)

    return make


def _leaks(sim, home, extra: list[str] | None = None) -> dict[str, list[str]]:
    needles = list(CANARIES.values())
    found: dict[str, list[str]] = {}
    for name, blobs in (("provider", sim.sent), ("aux", sim.aux_sent), ("tool_args", sim.tool_args_seen),
                        ("events", [json.dumps(sim.ctx.events, default=str)]), ("extra", extra or [])):
        for blob in blobs:
            for n in needles:
                if n in blob or n.lower() in blob.lower():
                    found.setdefault(name, []).append(n)
    for path, n in scan_files(home, needles):
        found.setdefault(f"file:{path}", []).append(n)
    return {k: sorted(set(v)) for k, v in found.items()}


def _mask_on(sid: str, mode: str = "standard") -> None:
    eng = plugin_engine.get_engine()
    assert eng.enable_session(sid, mode=mode, redact_pii=True)["ok"]


# --- control: the canaries really are visible when masking is off ---------------------------------


def test_control_without_masking_the_canaries_are_visible(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    plugin_engine.get_engine().enable_session("ctl-1", mode="standard", redact_pii=False)
    sim.turn("ctl-1", USER_TEXT, tool_outputs=[TOOL_OUTPUT])
    assert "provider" in _leaks(sim, isolated_hermes_env["home"])


# --- every outbound path ----------------------------------------------------------------------------


@pytest.mark.parametrize("api_mode", API_MODES)
def test_user_prompt_and_tool_results_never_leave(sim_factory, isolated_hermes_env, api_mode):
    sim = sim_factory(api_mode=api_mode)
    _mask_on("e2e-1")
    reply = sim.turn("e2e-1", USER_TEXT, tool_outputs=[TOOL_OUTPUT, TOOL_OUTPUT])
    assert "error" not in reply and "blocked" not in reply
    assert len(sim.sent) == 3
    assert _leaks(sim, isolated_hermes_env["home"]) == {}
    # The model still gets placeholders it can talk about.
    assert "[EMAIL_1]" in sim.sent[-1] and "[CARD_1]" in sim.sent[-1]


@pytest.mark.parametrize("api_mode", API_MODES)
def test_system_prompt_profile_is_masked(sim_factory, isolated_hermes_env, api_mode):
    sim = sim_factory(api_mode=api_mode, system_prompt=f"USER PROFILE: email {CANARIES['email']}, phone {CANARIES['phone']}")
    _mask_on("e2e-sys")
    sim.turn("e2e-sys", "hello")
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_every_retry_attempt_is_masked(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    _mask_on("e2e-retry")
    sim.turn("e2e-retry", USER_TEXT, transient_failures=2)
    assert len(sim.sent) == 3
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_model_reply_is_not_restored_into_history(sim_factory, isolated_hermes_env):
    """The fake model echoes the prompt. Restoring originals would write them to the transcript."""
    sim = sim_factory()
    _mask_on("e2e-echo")
    reply = sim.turn("e2e-echo", USER_TEXT)
    assert "[EMAIL_1]" in reply["content"]
    sim.turn("e2e-echo", "and again?")
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_title_and_compaction_aux_calls_and_new_head(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    _mask_on("e2e-cmp")
    sim.turn("e2e-cmp", USER_TEXT, tool_outputs=[TOOL_OUTPUT])
    sim.compact("e2e-cmp", "e2e-cmp-2")
    sim.turn("e2e-cmp-2", f"one more: {CANARIES['email']}", tool_outputs=[TOOL_OUTPUT])
    assert any('"task": "compression"' in a for a in sim.aux_sent)
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_subagent_inherits_masking(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    _mask_on("e2e-parent")
    sim.turn("e2e-parent", USER_TEXT)
    sim.spawn_subagent("e2e-parent", "e2e-child", "Summarize notes.txt", [TOOL_OUTPUT])
    eng = plugin_engine.get_engine()
    assert eng.is_incognito("e2e-child")
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_first_message_of_an_armed_chat_is_masked(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    eng = plugin_engine.get_engine()
    eng.arm_next_session(mode="strict", redact_pii=True)
    sim.hook("on_session_start", session_id="e2e-armed")
    sim.turn("e2e-armed", USER_TEXT)
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_turning_masking_on_applies_to_the_very_next_send(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    eng = plugin_engine.get_engine()
    eng.enable_session("e2e-race", mode="standard", redact_pii=False)
    sim.turn("e2e-race", "first, nothing personal")
    eng.enable_session("e2e-race", mode="standard", redact_pii=True)
    before = len(sim.sent)
    sim.turn("e2e-race", USER_TEXT)
    assert len(sim.sent) > before
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


@pytest.mark.parametrize("api_mode", API_MODES)
def test_images_and_files_are_withheld(sim_factory, isolated_hermes_env, api_mode):
    sim = sim_factory(api_mode=api_mode)
    _mask_on("e2e-img")
    image_type = {"chat_completions": "image_url", "codex_responses": "input_image",
                  "anthropic_messages": "image"}[api_mode]
    parts = [{"type": "text", "text": "what is in this picture?"},
             {"type": image_type, "image_url": {"url": "data:image/png;base64," + "QUJD" * 64}}]
    sim.turn("e2e-img", "what is in this picture?", parts=parts)
    assert sim.sent and all("base64" not in s for s in sim.sent)
    assert "withheld" in sim.sent[-1]


# --- fail closed --------------------------------------------------------------------------------------


def test_fail_closed_when_the_masker_raises(sim_factory, isolated_hermes_env, monkeypatch):
    sim = sim_factory()
    _mask_on("e2e-boom")
    pii_mod = getattr(plugin_engine, "pii", None)
    assert pii_mod is not None, "engine must use the pii module"

    def boom(*a, **k):
        raise RuntimeError("masker exploded")

    monkeypatch.setattr(pii_mod, "mask_text", boom)
    result = sim.turn("e2e-boom", USER_TEXT, tool_outputs=[TOOL_OUTPUT])
    assert sim.sent == []
    assert sim.aux_sent == []
    assert "blocked" in result or "error" in result
    assert _leaks(sim, isolated_hermes_env["home"]) == {}


def test_fail_closed_when_request_middleware_crashes(sim_factory, isolated_hermes_env, monkeypatch):
    """Hermes skips a crashing request middleware and continues; the execution gate must catch it."""
    sim = sim_factory()
    _mask_on("e2e-mw")
    eng = plugin_engine.get_engine()
    monkeypatch.setattr(eng, "transform_llm_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    sim.turn("e2e-mw", "plain text first")
    sim.history["e2e-mw"].append({"role": "user", "content": USER_TEXT})  # raw text slipped in history
    sim.turn("e2e-mw", "and now?")
    assert all(c not in s for s in sim.sent for c in CANARIES.values())


@pytest.mark.parametrize("where", ["system_prompt", "history_copy"])
def test_fail_closed_when_masking_misses_something(sim_factory, isolated_hermes_env, monkeypatch, where):
    """A masker bug that returns the payload untouched must stop the send, not leak it.

    ``system_prompt``: the value only exists in the provider payload. ``history_copy``: Hermes
    hands the plugin copies of the messages, so masking them in place has no effect.
    """
    if where == "system_prompt":
        sim = sim_factory(system_prompt=f"USER PROFILE: {USER_TEXT}")
    else:
        sim = sim_factory()
        sim.history["e2e-miss"] = [{"role": "user", "content": USER_TEXT}]
        monkeypatch.setattr(plugin_engine.IncognitoEngine, "mask_messages_in_place", lambda self, sid, msgs: 0)
    _mask_on("e2e-miss")
    monkeypatch.setattr(plugin_engine.pii, "mask_payload", lambda payload, vault, report=None: payload)
    result = sim.turn("e2e-miss", "go on")
    assert sim.sent == []
    assert "error" in result or "blocked" in result
    assert "couldn't confirm your personal details were masked" in str(result)
    assert all(c not in str(result) for c in CANARIES.values())


# --- nothing written or served contains the values -----------------------------------------------------


def test_status_rest_rpc_slash_and_logs_carry_no_values(sim_factory, isolated_hermes_env, caplog):
    caplog.set_level(logging.DEBUG)
    sim = sim_factory()
    _mask_on("e2e-api", mode="strict")
    sim.turn("e2e-api", USER_TEXT, tool_outputs=[TOOL_OUTPUT])
    outputs = [
        json.dumps(plugin_api.get_status(session_id="e2e-api"), default=str),
        json.dumps(sim.ctx.rpcs["status"]({"session_id": "e2e-api"}), default=str),
        json.dumps(plugin_api.verify_session({"session_id": "e2e-api"}), default=str),
        str(sim.ctx.commands["incognito"]("status", session_id="e2e-api")),
        caplog.text,
    ]
    assert _leaks(sim, isolated_hermes_env["home"], extra=outputs) == {}


def test_burn_clears_the_ram_vault(sim_factory, isolated_hermes_env):
    sim = sim_factory()
    _mask_on("e2e-burn")
    sim.turn("e2e-burn", USER_TEXT)
    eng = plugin_engine.get_engine()
    assert eng.get_vault_entry("e2e-burn", "[EMAIL_1]") == CANARIES["email"]
    eng.burn_session("e2e-burn")
    assert eng.get_vault_entry("e2e-burn", "[EMAIL_1]") is None


# --- fuzzing --------------------------------------------------------------------------------------------


def _luhn_card(rng: random.Random) -> str:
    body = [4] + [rng.randrange(10) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(body)):
        d = d * 2 if i % 2 == 0 else d
        total += d - 9 if d > 9 else d
    digits = "".join(map(str, body + [(10 - total % 10) % 10]))
    sep = rng.choice(["", " ", "-"])
    return sep.join(digits[i:i + 4] for i in range(0, 16, 4)) if sep else digits


def _random_pii(rng: random.Random) -> str:
    user = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 10)))
    kind = rng.randrange(8)
    if kind == 0:
        return f"{user}.{rng.randint(1, 999)}@{rng.choice(['gmail.com', 'empresa.co', 'uni.edu.co', 'x.io'])}"
    if kind == 1:
        return f"+57 3{rng.randint(0, 5)}{rng.randint(0, 9)} {rng.randint(100, 999)} {rng.randint(1000, 9999)}"
    if kind == 2:
        return _luhn_card(rng)
    if kind == 3:
        return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if kind == 4:
        return "sk-proj-" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(28))
    if kind == 5:
        return f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
    if kind == 6:
        return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))
    return f"{user} [at] {rng.choice(['acme', 'mail'])} [dot] com"


@pytest.mark.parametrize("seed", range(25))
def test_seeded_fuzz_pii_in_random_text_never_leaves(sim_factory, isolated_hermes_env, seed):
    rng = random.Random(seed)
    values = [_random_pii(rng) for _ in range(rng.randint(1, 5))]
    words = ["".join(rng.choice(string.ascii_letters + " ,.;:()\n") for _ in range(rng.randint(0, 30)))
             for _ in values]
    text = "".join(w + " " + v + " " for w, v in zip(words, values))
    sim = sim_factory(api_mode=rng.choice(API_MODES))
    _mask_on(f"fz-{seed}")
    sim.turn(f"fz-{seed}", text, tool_outputs=[" | ".join(reversed(values))])
    blobs = sim.sent + sim.aux_sent
    for v in values:
        assert all(v not in b for b in blobs), v


def test_execution_gate_blocks_even_without_hermes_internals(isolated_hermes_env, monkeypatch):
    """If Hermes' _DownstreamExecutionError is unavailable, the gate escapes with a BaseException,
    which Hermes' `except Exception` skip-and-send path cannot swallow."""
    import sys

    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    from hermes_sim import SimCtx

    ctx = SimCtx()
    plugin.register(ctx)
    _mask_on("e2e-gate")
    sent: list = []
    gate = ctx.middleware["llm_execution"][0]
    request = {"messages": [{"role": "user", "content": USER_TEXT}]}
    monkeypatch.setattr(plugin_engine.pii, "mask_payload", lambda payload, vault, report=None: payload)
    with pytest.raises(BaseException) as info:
        try:
            gate(request, sent.append, session_id="e2e-gate")
        except Exception as exc:  # what Hermes would catch and then send anyway
            pytest.fail(f"gate raised a plain Exception ({type(exc).__name__}); Hermes would send")
    assert not isinstance(info.value, Exception)
    assert sent == []
    assert all(c not in str(info.value) for c in CANARIES.values())


def test_execution_gate_passes_clean_requests_unchanged_when_masking_is_off(isolated_hermes_env):
    from hermes_sim import SimCtx

    ctx = SimCtx()
    plugin.register(ctx)
    eng = plugin_engine.get_engine()
    eng.enable_session("e2e-off", mode="standard", redact_pii=False)
    gate = ctx.middleware["llm_execution"][0]
    sent: list = []
    request = {"messages": [{"role": "user", "content": USER_TEXT}]}
    gate(request, sent.append, session_id="e2e-off")
    assert sent == [request]
