import sys
import copy
from pathlib import Path
import pytest

PROJECT_ROOT = Path("C:/Users/nicol/Downloads/Proyectos personales/hermes-incognito").resolve()
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


def test_transform_pii_redaction_and_restoration(isolated_hermes_env):
    """
    redact_pii=True replaces synthetic emails and phone numbers with [REDACTED_EMAIL_1] / [REDACTED_PHONE_1],
    and transform_llm_response restores the exact original values in assistant text.
    After burn_session, the RAM vault is emptied.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
    if hasattr(eng, "config"):
        eng.config["redact_outbound_pii"] = True

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
    assert "[REDACTED_EMAIL_" in trans_content or "[REDACTED_" in trans_content

    # Simulate assistant response repeating back the token
    assistant_text = f"Received notification for token in: {trans_content}"
    resp = {"choices": [{"message": {"role": "assistant", "content": assistant_text}}]}

    restored_resp = eng.transform_llm_response(sess_id, resp)
    assert restored_resp is not None
    restored_content = restored_resp["choices"][0]["message"]["content"]

    assert original_email in restored_content
    assert original_phone in restored_content

    # Burn session and verify RAM vault is empty
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
