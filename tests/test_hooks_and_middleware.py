import sys
import copy
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import engine
    IncognitoEngine = getattr(engine, "IncognitoEngine", None)
except ImportError:
    engine = None
    IncognitoEngine = None


def test_evaluate_tool_guard_non_incognito(isolated_hermes_env):
    """Non-incognito session -> returns None for memory and skill_manage."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-tool-guard-non-incognito"
    assert eng.evaluate_tool_guard(sess_id, "memory", {"operations": [{"action": "add", "content": "note"}]}) is None
    assert eng.evaluate_tool_guard(sess_id, "skill_manage", {"operations": []}) is None
    assert eng.evaluate_tool_guard(sess_id, "read_file", {"path": "a.txt"}) is None


def test_evaluate_tool_guard_standard_mode(isolated_hermes_env):
    """Standard incognito blocks memory and skill_manage, allows read_file/web_search."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-tool-guard-standard"
    eng.enable_session(sess_id, mode="standard")

    # memory and skill_manage should be blocked
    res_mem = eng.evaluate_tool_guard(sess_id, "memory", {"operations": [{"action": "add", "content": "note"}]})
    assert res_mem is not None
    assert res_mem.get("action") == "block"

    res_skill = eng.evaluate_tool_guard(sess_id, "skill_manage", {"operations": []})
    assert res_skill is not None
    assert res_skill.get("action") == "block"

    # read_file and web_search allowed
    res_read = eng.evaluate_tool_guard(sess_id, "read_file", {"path": "test.txt"})
    assert res_read is None or res_read.get("action") == "allow" or res_read.get("action") == "approve"

    res_search = eng.evaluate_tool_guard(sess_id, "web_search", {"query": "python"})
    assert res_search is None or res_search.get("action") == "allow" or res_search.get("action") == "approve"


def test_evaluate_tool_guard_strict_mode(isolated_hermes_env):
    """Strict incognito blocks session_search, cronjob_manage, memory, skill_manage, and approves send_message."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-tool-guard-strict"
    eng.enable_session(sess_id, mode="strict")

    res_sess_search = eng.evaluate_tool_guard(sess_id, "session_search", {"query": "test"})
    assert res_sess_search is not None
    assert res_sess_search.get("action") == "block"

    res_cron = eng.evaluate_tool_guard(sess_id, "cronjob_manage", {"action": "list"})
    assert res_cron is not None
    assert res_cron.get("action") == "block"

    res_msg = eng.evaluate_tool_guard(sess_id, "send_message", {"content": "hello"})
    assert res_msg is not None
    assert res_msg.get("action") == "approve"


def test_transform_llm_request_and_response_non_incognito(isolated_hermes_env):
    """Non-incognito session -> returns None for transform_llm_request and transform_llm_response."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-transform-normal"
    req = {"messages": [{"role": "user", "content": "hello world"}]}
    resp = {"choices": [{"message": {"role": "assistant", "content": "hello there"}}]}

    assert eng.transform_llm_request(sess_id, req) is None
    assert eng.transform_llm_response(sess_id, resp) is None


def test_transform_llm_request_strict_memory_stripping(isolated_hermes_env):
    """
    Strict mode strips MEMORY (your personal notes) and USER PROFILE sections
    from outgoing system/user messages copy without mutating the original request dict!
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-transform-strict"
    eng.enable_session(sess_id, mode="strict")

    system_content = (
        "You are Hermes Agent.\n\n"
        "══════════════════════════════════════════════\n"
        "MEMORY (your personal notes)\n"
        "Personal info here\n"
        "══════════════════════════════════════════════\n"
        "USER PROFILE (who the user is)\n"
        "User info here\n"
        "══════════════════════════════════════════════\n"
        "Follow rules strictly."
    )

    req = {
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": "Check secrets"}
        ]
    }
    req_copy = copy.deepcopy(req)

    transformed = eng.transform_llm_request(sess_id, req)
    assert transformed is not None
    import json
    assert json.dumps(transformed)

    # Verify caller's original request was NOT mutated
    assert req == req_copy

    rewritten_req = transformed["request"]
    assert "request" not in rewritten_req
    assert "source" not in rewritten_req
    trans_system_content = rewritten_req["messages"][0]["content"]
    assert "MEMORY (your personal notes)" not in trans_system_content
    assert "USER PROFILE (who the user is)" not in trans_system_content
    assert "Personal info here" not in trans_system_content
    assert "User info here" not in trans_system_content
    assert "Follow rules strictly." in trans_system_content


def test_transform_pii_masks_and_never_restores(isolated_hermes_env):
    """
    redact_pii=True replaces synthetic emails and phone numbers with stable [EMAIL_1] / [PHONE_1]
    placeholders. Replies are left as the model wrote them: originals are never put back into
    anything Hermes stores. After burn_session, the RAM vault is emptied.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-transform-pii"
    eng.enable_session(sess_id, mode="standard", redact_pii=True)

    original_email = "alice.smith@example.org"
    original_phone = "+1-415-555-0199"

    user_text = f"Contact me at {original_email} or {original_phone} for verification."
    req = {"messages": [{"role": "user", "content": user_text}]}

    transformed_req = eng.transform_llm_request(sess_id, req)
    assert transformed_req is not None
    import json
    assert json.dumps(transformed_req)
    trans_content = transformed_req["request"]["messages"][0]["content"]

    assert original_email not in trans_content
    assert original_phone not in trans_content
    assert trans_content == "Contact me at [EMAIL_1] or [PHONE_1] for verification."

    # The same value gets the same placeholder on the next request.
    again = eng.transform_llm_request(sess_id, {"messages": [{"role": "user", "content": original_email}]})
    assert again["request"]["messages"][0]["content"] == "[EMAIL_1]"

    resp = {"choices": [{"message": {"role": "assistant", "content": f"Noted: {trans_content}"}}]}
    assert eng.transform_llm_response(sess_id, resp) is None

    eng.burn_session(sess_id, reason="test_cleanup")
    zero_trace = eng.verify_zero_trace(sess_id)
    assert zero_trace.get("ram_vault_entries") == 0


def test_provider_zdr_hints_metadata(isolated_hermes_env):
    """provider_zdr_hints=True attaches safe ZDR metadata without corrupting messages list."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
    if hasattr(eng, "config"):
        eng.config["provider_zdr_hints"] = True

    sess_id = "sess-zdr-hints"
    eng.enable_session(sess_id, mode="standard")

    plain_req = {"messages": [{"role": "user", "content": "Safe query"}]}
    assert eng.transform_llm_request(sess_id, plain_req) is None

    req = {
        "base_url": "https://openrouter.ai/api/v1",
        "store": True,
        "messages": [{"role": "user", "content": "Safe query"}],
    }
    transformed = eng.transform_llm_request(sess_id, req)

    assert transformed is not None
    rewritten = transformed["request"]
    assert rewritten["store"] is False
    assert rewritten["extra_body"]["provider"]["data_collection"] == "deny"
    assert isinstance(rewritten["messages"], list)
    assert len(rewritten["messages"]) == 1
    assert rewritten["messages"][0]["content"] == "Safe query"


def test_transform_llm_request_real_hermes_double_bar_and_anthropic_system(isolated_hermes_env):
    """
    Regression test: Real Hermes system prompts wrap MEMORY and USER PROFILE headers
    between TWO ══════ divider bars and end before 'Active Hermes profile:' (no trailing bar).
    Also verifies Anthropic 'system' and Codex 'instructions' top-level fields are stripped.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
    sess_id = "sess-real-double-bar"
    eng.enable_session(sess_id, mode="strict")

    real_hermes_prompt = (
        "Only proceed without loading a skill if genuinely none are relevant to the task.\n\n"
        "══════════════════════════════════════════════\n"
        "MEMORY (your personal notes) [99% — 3,984/4,000 chars]\n"
        "══════════════════════════════════════════════\n"
        "Workspace scratch: C:\\Temp\n"
        "§\n"
        "Secret favorite color note: azul cobalto\n\n"
        "══════════════════════════════════════════════\n"
        "USER PROFILE (who the user is) [96% — 2,897/3,000 chars]\n"
        "══════════════════════════════════════════════\n"
        "User's name: Nicolás.\n"
        "§\n"
        "Location: Cali.\n\n"
        "Active Hermes profile: default.\n\n"
        "Conversation started: Wednesday, November 11, 2026\n\n"
        "# Hermes runtime environment\n\nHost: Windows (11)"
    )

    # 1. OpenAI/Gemini messages format
    req_chat = {
        "messages": [
            {"role": "system", "content": real_hermes_prompt},
            {"role": "user", "content": "Cual es mi color favorito?"},
        ]
    }
    res_chat = eng.transform_llm_request(sess_id, req_chat)
    assert res_chat is not None
    cleaned = res_chat["request"]["messages"][0]["content"]
    assert "MEMORY (your personal notes)" not in cleaned
    assert "USER PROFILE (who the user is)" not in cleaned
    assert "azul cobalto" not in cleaned
    assert "User's name: Nicolás." not in cleaned
    assert "Active Hermes profile: default." in cleaned
    assert "# Hermes runtime environment" in cleaned

    # 2. Anthropic top-level system + Codex instructions format
    req_anth = {
        "system": [{"type": "text", "text": real_hermes_prompt}],
        "instructions": real_hermes_prompt,
        "messages": [{"role": "user", "content": "Hello"}],
    }
    res_anth = eng.transform_llm_request(sess_id, req_anth)
    assert res_anth is not None
    assert "azul cobalto" not in res_anth["request"]["system"][0]["text"]
    assert "azul cobalto" not in res_anth["request"]["instructions"]


def test_cross_session_search_scrubbing_and_direct_read_block(isolated_hermes_env):
    """
    Regression test: Normal non-incognito sessions cannot read or discover active
    incognito sessions via session_search or deferred tool_call.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    import json
    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    incog_sid = "local-incognito-secret-chat"
    normal_sid = "local-normal-public-chat"
    eng.enable_session(incog_sid, mode="strict")

    # Direct read of incognito session from a normal session is blocked
    guard_direct = eng.evaluate_tool_guard(normal_sid, "session_search", {"session_id": incog_sid})
    assert guard_direct is not None and guard_direct["action"] == "block"

    # Wrapped deferred tool_call targeting incognito session is also blocked
    guard_wrapped = eng.evaluate_tool_guard(
        normal_sid,
        "tool_call",
        {"calls": [{"name": "session_search", "arguments": {"session_id": incog_sid}}]},
    )
    assert guard_wrapped is not None and guard_wrapped["action"] == "block"

    # Discovery search from normal session scrubs incognito session hits from JSON result
    raw_search_result = json.dumps({
        "success": True,
        "mode": "discover",
        "query": "color favorito",
        "count": 2,
        "results": [
            {"session_id": incog_sid, "title": "Recordar color favorito stiven", "snippet": "stiven"},
            {"session_id": "local-older-public", "title": "Tema publico", "snippet": "hola"},
        ],
    })
    scrubbed_str = eng.scrub_tool_result(normal_sid, "session_search", {"query": "color favorito"}, raw_search_result)
    assert scrubbed_str is not None
    scrubbed = json.loads(scrubbed_str)
    assert scrubbed["count"] == 1
    assert len(scrubbed["results"]) == 1
    assert scrubbed["results"][0]["session_id"] == "local-older-public"
    assert "stiven" not in scrubbed_str

    # Raw execute_code / terminal bypass attempting to open state.db directly is blocked while incognito is active
    guard_exec = eng.evaluate_tool_guard(
        normal_sid,
        "execute_code",
        {"code": 'import sqlite3\nconn = sqlite3.connect("C:/Users/nicol/AppData/Local/hermes/state.db")'},
    )
    assert guard_exec is not None and guard_exec["action"] == "block"

    # Raw output line scrubbing for execute_code / terminal as defense-in-depth
    raw_exec_out = f"109547 {incog_sid} Mi color favorito es forsaken\n109549 {normal_sid} Hola\n"
    scrubbed_exec = eng.scrub_tool_result(normal_sid, "execute_code", {}, raw_exec_out)
    assert scrubbed_exec is not None
    assert "forsaken" not in scrubbed_exec
    assert "Hola" in scrubbed_exec
