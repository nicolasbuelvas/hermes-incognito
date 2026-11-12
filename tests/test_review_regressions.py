"""Regression tests for the lineage, mode-switch, scoping, and API fixes."""

import importlib.util
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import engine  # noqa: E402
from engine import IncognitoEngine  # noqa: E402


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
from hermes_plugin_incognito_test.dashboard import plugin_api  # noqa: E402
from hermes_plugin_incognito_test.tools import incognito_control  # noqa: E402


class _Ctx:
    def __init__(self):
        self.hooks, self.commands, self.rpcs, self.events = {}, {}, {}, []

    def register_tool(self, name, **kwargs):
        pass

    def register_hook(self, name, fn, **kwargs):
        self.hooks[name] = fn

    def register_middleware(self, kind, fn):
        pass

    def register_command(self, name, handler, **kwargs):
        self.commands[name] = handler

    def register_cli_command(self, *args, **kwargs):
        pass

    def register_rpc(self, name, fn):
        self.rpcs[name] = fn

    def register_skill(self, *args, **kwargs):
        pass

    def emit_to_session(self, session_id, event, payload=None):
        self.events.append((session_id, event, payload))


def _transcript(env, sid: str) -> Path:
    path = env["sessions_dir"] / f"{sid}.jsonl"
    path.write_text('{"role": "user", "content": "private"}\n', encoding="utf-8")
    return path


def _db_rows(env, *sids: str) -> None:
    with sqlite3.connect(env["mock_db"].db_path) as conn:
        for sid in sids:
            conn.execute("INSERT INTO sessions (id) VALUES (?)", (sid,))
            conn.execute("INSERT INTO messages (id, session_id, content) VALUES (?, ?, ?)", (f"m-{sid}", sid, "x"))


def _compacted_pair(env, ttl: int = 1):
    eng = IncognitoEngine(home_dir=env["home"])
    eng.enable_session("parent", mode="strict", ttl_minutes=ttl)
    assert eng.propagate_compaction("parent", "child")["ok"]
    eng.touch_session("child")
    return eng


# --- 1. Lineage: TTL/sweep/finalize never cascades to a live descendant -------------------------


def test_sweep_of_expired_compacted_parent_keeps_live_child(isolated_hermes_env):
    eng = _compacted_pair(isolated_hermes_env)
    parent_file = _transcript(isolated_hermes_env, "parent")
    child_file = _transcript(isolated_hermes_env, "child")
    # The parent's original deadline passes while the child is still active.
    eng.set_session_expiry("parent", time.time() - 5)

    eng.sweep_expired()

    assert eng.is_incognito("child")
    assert child_file.exists()
    # The ancestor is not swept on its own TTL; it is deleted with the live head.
    assert eng.is_incognito("parent")
    assert parent_file.exists()


def test_dead_owner_pid_on_ancestor_does_not_sweep_live_child(isolated_hermes_env):
    eng = _compacted_pair(isolated_hermes_env, ttl=60)
    child_file = _transcript(isolated_hermes_env, "child")
    leases = eng._read_leases()
    leases["parent"]["owner_pid"] = 2**22 + 12345  # not a live pid
    eng._write_leases(leases)

    eng.sweep_expired()

    assert eng.is_incognito("child")
    assert child_file.exists()


def test_finalize_of_compacted_parent_keeps_live_child(isolated_hermes_env):
    ctx = _Ctx()
    plugin_init.register(ctx)
    eng = plugin_init.get_engine()
    eng.enable_session("parent", ttl_minutes=60)
    eng.propagate_compaction("parent", "child")
    child_file = _transcript(isolated_hermes_env, "child")

    ctx.hooks["on_session_finalize"](session_id="parent")
    ctx.hooks["on_session_reset"](session_id="parent")

    assert eng.is_incognito("child")
    assert child_file.exists()


def test_expired_head_sweep_burns_head_and_ancestors(isolated_hermes_env):
    eng = _compacted_pair(isolated_hermes_env)
    files = [_transcript(isolated_hermes_env, sid) for sid in ("parent", "child")]
    eng.set_session_expiry("child", time.time() - 5)

    eng.sweep_expired()

    assert not eng.is_incognito("child")
    assert not eng.is_incognito("parent")
    assert not any(f.exists() for f in files)


def test_manual_burn_of_head_cleans_ancestors(isolated_hermes_env, monkeypatch):
    monkeypatch.setattr(engine, "SessionDB", type(isolated_hermes_env["mock_db"]))
    _db_rows(isolated_hermes_env, "grandparent", "parent", "child")
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    eng.enable_session("grandparent", ttl_minutes=60)
    eng.propagate_compaction("grandparent", "parent")
    eng.propagate_compaction("parent", "child")
    files = [_transcript(isolated_hermes_env, sid) for sid in ("grandparent", "parent", "child")]

    result = eng.burn_session("child", reason="slash_burn")

    assert result["ok"] and not result["pending_burn"]
    assert not any(f.exists() for f in files)
    for sid in ("grandparent", "parent", "child"):
        assert not eng.is_incognito(sid)
        assert isolated_hermes_env["mock_db"].get_session(sid) is None


def test_burn_of_ancestor_never_deletes_live_head(isolated_hermes_env, monkeypatch):
    """Hermes deletes a whole compression conversation from any segment; fence the live head out."""
    mock_type = type(isolated_hermes_env["mock_db"])
    monkeypatch.setattr(engine, "SessionDB", mock_type)
    monkeypatch.setattr(
        mock_type, "get_session_delete_targets",
        lambda db, sid: [sid] + (["child"] if sid == "parent" else []),
    )
    _db_rows(isolated_hermes_env, "parent", "child")
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda *a, **kw: None)
    eng.enable_session("parent", ttl_minutes=60)
    eng.propagate_compaction("parent", "child")
    child_file = _transcript(isolated_hermes_env, "child")

    eng.burn_session("parent", reason="desktop_burn")

    assert eng.get_session_state("child")["pending_burn"] is False
    assert child_file.exists()
    assert isolated_hermes_env["mock_db"].get_session("child") is not None


def test_orphaned_ancestor_is_swept_when_head_is_gone(isolated_hermes_env):
    eng = _compacted_pair(isolated_hermes_env)
    parent_file = _transcript(isolated_hermes_env, "parent")
    leases = eng._read_leases()
    leases.pop("child")
    eng._write_leases(leases)

    eng.sweep_expired()

    assert not eng.is_incognito("parent")
    assert not parent_file.exists()


def test_disable_keep_on_head_releases_ancestors(isolated_hermes_env):
    eng = _compacted_pair(isolated_hermes_env)
    parent_file = _transcript(isolated_hermes_env, "parent")

    assert eng.disable_session("child")["ok"]
    eng.sweep_expired()

    assert not eng.is_incognito("parent")
    assert parent_file.exists()


# --- 2. Empty /incognito shows status ---------------------------------------------------------


def test_empty_slash_command_shows_status_without_toggling(isolated_hermes_env):
    ctx = _Ctx()
    plugin_init.register(ctx)
    eng = plugin_init.get_engine()
    slash = ctx.commands["incognito"]
    slash("on", session_id="sess-empty")

    assert slash("", session_id="sess-empty") == slash("status", session_id="sess-empty")
    assert "Incognito Active" in slash("", session_id="sess-empty")
    assert eng.is_incognito("sess-empty")
    assert eng.get_session_state("sess-empty")["mode"] == "standard"

    # Without a session it must not arm anything either.
    assert slash("", session_id="") == slash("status", session_id="")
    assert eng.get_armed_state() is None

    # Explicit toggle still flips the mode.
    assert "disabled" in slash("toggle", session_id="sess-empty").lower()
    assert not eng.is_incognito("sess-empty")


# --- 3. Mode switch / re-enable preserve the lease -----------------------------------------------


def test_mode_switch_preserves_lineage_counters_and_redaction(isolated_hermes_env):
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    eng.enable_session("parent", mode="standard", ttl_minutes=30, redact_pii=True)
    eng.propagate_compaction("parent", "child")
    eng._record_blocked_write("child")
    leases = eng._read_leases()
    leases["child"]["redactions"] = 4
    eng._write_leases(leases)
    before = eng._read_leases()["child"]
    protected_before = eng._read_audit()["sessions_protected"]

    assert eng.toggle_session("child", mode="strict")["ok"]
    after = eng._read_leases()["child"]
    assert after["mode"] == "strict"
    for key in ("lineage_ids", "blocked_writes", "redactions", "started_at", "redact_pii", "ttl_minutes"):
        assert after[key] == before[key], key
    assert eng._read_audit()["sessions_protected"] == protected_before

    # REST toggle and re-enable keep the lease too.
    plugin_api.toggle_session({"session_id": "child", "mode": "standard"})
    eng.enable_session("child", mode="standard")
    after = eng._read_leases()["child"]
    assert after["mode"] == "standard"
    assert after["lineage_ids"] == before["lineage_ids"]
    assert after["redact_pii"] is True
    assert after["blocked_writes"] == 1

    # Explicit values still apply.
    eng.enable_session("child", mode="standard", ttl_minutes=5, redact_pii=False)
    after = eng._read_leases()["child"]
    assert after["ttl_minutes"] == 5 and after["redact_pii"] is False


# --- 4. Session ID validation ------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["bad.id", "../x", "a/b", "", "x" * 200])
def test_entry_points_reject_invalid_session_ids(isolated_hermes_env, bad):
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    eng.enable_session("good", ttl_minutes=10)

    assert not eng.enable_session(bad)["ok"]
    assert not eng.disable_session(bad)["ok"]
    assert not eng.set_session_ttl(bad, 5)["ok"]
    assert not eng.propagate_compaction("good", bad)["ok"]
    assert not eng.propagate_compaction(bad, "good2")["ok"]
    eng.arm_next_session()
    assert eng.consume_armed_session(bad) is None
    assert eng.get_armed_state() is not None
    assert set(eng._read_leases()) == {"good"}


# --- 5. Model-facing status is scoped ------------------------------------------------------------


def test_model_tool_status_is_scoped_to_current_session(isolated_hermes_env):
    for sid in ("mine-session-1", "other-session-2"):
        assert json.loads(incognito_control({"action": "enable"}, conversation_id=sid))["ok"]

    status = json.loads(incognito_control({"action": "status"}, conversation_id="mine-session-1"))
    assert status["incognito"] is True
    blob = json.dumps(status)
    assert "other-session-2" not in blob and "othe" not in blob
    assert "audit" not in status and "active_sessions" not in status and "active_count" not in status
    assert "receipts" not in blob

    # The operator view keeps the full picture.
    full = plugin_init.get_engine().status_summary("mine-session-1")
    assert full["active_count"] == 2 and "audit" in full


# --- 6. Skill wording ----------------------------------------------------------------------------


def test_skill_does_not_promise_target_session_control():
    text = (PROJECT_ROOT / "skills" / "incognito-privacy" / "SKILL.md").read_text(encoding="utf-8")
    assert "current or target session" not in text


# --- 7. REST /verify propagates ok ---------------------------------------------------------------


def test_rest_verify_propagates_failure(isolated_hermes_env):
    assert plugin_api.verify_session({"session_id": "bad.id"})["ok"] is False
    assert plugin_api.verify_session({"session_id": "clean-session"})["ok"] is True


# --- 8. PermissionError means alive -------------------------------------------------------------


def test_pid_permission_error_counts_as_alive(monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", None)
    monkeypatch.setattr(engine.os, "name", "posix")

    def _raise(exc):
        def _kill(pid, sig):
            raise exc
        return _kill

    monkeypatch.setattr(engine.os, "kill", _raise(PermissionError()))
    assert engine._is_pid_alive(4242) is True
    monkeypatch.setattr(engine.os, "kill", _raise(ProcessLookupError()))
    assert engine._is_pid_alive(4242) is False


# --- LOW ----------------------------------------------------------------------------------------


def test_unused_strict_memory_pattern_removed():
    assert not hasattr(engine, "_STRICT_MEMORY_BLOCKS")


def test_single_bar_strip_keeps_unrelated_separators():
    text = (
        "Intro\n\n"
        "Table:\n=====\nkeep me\n\n"
        "══════════\nMEMORY (your personal notes)\nsecret note\n"
        "══════════\nFollow rules.\n\n"
        "Footer\n----------\nend"
    )
    cleaned = IncognitoEngine._strip_memory_blocks(text)
    assert "secret note" not in cleaned and "MEMORY" not in cleaned
    assert "=====\nkeep me" in cleaned
    assert "----------\nend" in cleaned
    assert "Follow rules." in cleaned
    assert "══════════" not in cleaned


def test_tests_never_use_a_real_sessiondb():
    assert engine.SessionDB is None
    hermes_paths = [p for p in sys.path if "hermes-agent" in p.replace("\\", "/")]
    assert not hermes_paths
