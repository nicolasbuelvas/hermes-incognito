"""Saving an Incognito chat to normal history, with confirmation and undo."""

from __future__ import annotations

import json
import time

import pytest
from conftest import MockSessionDB
from hermes_sim import (
    SimCtx,
    SimHermes,
    install_fake_hermes_middleware,
    load_plugin,
    scan_files,
)

plugin = load_plugin()
from hermes_plugin_incognito_test import engine as plugin_engine
from hermes_plugin_incognito_test.dashboard import plugin_api

EMAIL = "save.canary.42@example.org"


@pytest.fixture
def db(isolated_hermes_env, monkeypatch):
    monkeypatch.setattr(plugin_engine, "SessionDB", MockSessionDB)
    return isolated_hermes_env["mock_db"]


@pytest.fixture
def eng(isolated_hermes_env):
    return plugin_engine.get_engine()


@pytest.fixture
def clock(monkeypatch):
    state = {"now": time.time()}
    monkeypatch.setattr(plugin_engine.time, "time", lambda: state["now"])
    return state


def _transcript(home, sid, text="hello"):
    path = home / "sessions" / f"{sid}.jsonl"
    path.write_text(json.dumps({"role": "user", "content": text}) + "\n", encoding="utf-8")
    return path


def _start(eng, db, sid, **kw):
    db.create_session(sid)
    res = eng.enable_session(sid, **kw)
    assert res["ok"], res
    return res


def _hidden(db, sid):
    return bool((db.get_session(sid) or {}).get("hidden"))


# --- save -> kept -----------------------------------------------------------------------------------


def test_save_moves_chat_to_history_and_survives_sweep_and_burn(eng, db, isolated_hermes_env, clock):
    home = isolated_hermes_env["home"]
    _start(eng, db, "s1", ttl_minutes=1)
    transcript = _transcript(home, "s1")
    res = eng.save_session("s1")
    assert res["ok"] and res["saved"] and res["undo_seconds"] == 600
    assert not eng.is_incognito("s1")
    assert not _hidden(db, "s1")
    assert db.get_session_model_config_value("s1", "incognito") is None
    clock["now"] += 3600  # long past the old TTL and the undo window
    eng.sweep_expired()
    assert transcript.exists() and db.get_session("s1") is not None
    burn = eng.burn_session("s1", reason="test")
    assert not burn.get("ok") or burn.get("db_deleted") in (0, False, None)
    assert transcript.exists() and db.get_session("s1") is not None
    assert eng.saved_state("s1") is None  # undo window over
    assert eng.undo_save("s1")["ok"] is False


def test_saved_record_is_content_free(eng, db, isolated_hermes_env):
    _start(eng, db, "s-cf", redact_pii=True)
    eng.mask_text("s-cf", f"mail {EMAIL}")
    eng.save_session("s-cf")
    saved = (isolated_hermes_env["plugin_data_dir"] / "saved.json").read_text()
    assert EMAIL not in saved and "s-cf" in saved
    assert scan_files(isolated_hermes_env["home"], [EMAIL]) == []


# --- undo -> Incognito again --------------------------------------------------------------------------


def test_undo_restores_incognito_with_same_settings_and_burns_on_sweep(eng, db, isolated_hermes_env, clock):
    home = isolated_hermes_env["home"]
    _start(eng, db, "s2", mode="strict", ttl_minutes=5, redact_pii=True)
    before = eng.get_session_state("s2")
    eng.save_session("s2")
    _transcript(home, "s2", "written while saved")  # written between save and undo
    clock["now"] += 60
    res = eng.undo_save("s2")
    assert res["ok"] and res["mode"] == "strict" and res["redact_pii"] is True and res["ttl_minutes"] == 5
    after = eng.get_session_state("s2")
    assert after["active"] and after["mode"] == "strict" and after["redact_pii"] is True
    assert after["started_at"] == before["started_at"]
    assert _hidden(db, "s2")
    assert eng.saved_state("s2") is None
    clock["now"] += 6 * 60
    eng.sweep_expired()
    assert not (home / "sessions" / "s2.jsonl").exists()
    assert db.get_session("s2") is None


def test_undo_after_window_or_close_is_refused(eng, db, clock):
    _start(eng, db, "s3")
    eng.save_session("s3")
    clock["now"] += 11 * 60
    assert eng.undo_save("s3") == {"ok": False, "error": "Undo is no longer available for this chat."}
    _start(eng, db, "s4")
    eng.save_session("s4")
    plugin_ctx_cleanup = plugin_engine.get_engine().end_save_undo
    plugin_ctx_cleanup("s4")
    assert eng.undo_save("s4")["ok"] is False


def test_cancel_changes_nothing(eng, db):
    """Desktop's Cancel and the CLI's "n" never call save; the slash command needs `confirm`."""
    ctx = SimCtx()
    plugin.register(ctx)
    _start(eng, db, "s5", redact_pii=True)
    text = ctx.commands["incognito"]("save", session_id="s5")
    assert "/incognito save confirm" in text and "stay masked" in text
    assert eng.is_incognito("s5") and eng.saved_state("s5") is None and _hidden(db, "s5")


# --- lineage, ancestors, sub-agents, pending burn -------------------------------------------------


def test_save_and_undo_cover_compacted_ancestors(eng, db, isolated_hermes_env, clock):
    home = isolated_hermes_env["home"]
    _start(eng, db, "old", ttl_minutes=5)
    db.create_session("new")
    assert eng.propagate_compaction("old", "new")["ok"]
    _transcript(home, "old"); _transcript(home, "new")
    assert eng.save_session("old")["ok"] is False  # earlier segment, not the live head
    assert eng.save_session("new")["ok"]
    assert not eng.is_incognito("old") and not eng.is_incognito("new")
    assert not _hidden(db, "old") and not _hidden(db, "new")
    assert eng.undo_save("new")["ok"]
    assert eng.is_incognito("old") and eng.is_incognito("new")
    assert _hidden(db, "old") and _hidden(db, "new")
    clock["now"] += 6 * 60
    eng.sweep_expired()
    assert not (home / "sessions" / "old.jsonl").exists()
    assert not (home / "sessions" / "new.jsonl").exists()


def test_compaction_during_undo_window_moves_the_undo(eng, db, isolated_hermes_env):
    _start(eng, db, "c-old", redact_pii=True)
    eng.save_session("c-old")
    db.create_session("c-new")
    eng.propagate_compaction("c-old", "c-new")
    assert eng.saved_state("c-new") is not None and eng.saved_state("c-old") is None
    assert eng.masking_active("c-new")
    assert eng.undo_save("c-new")["ok"]
    assert eng.is_incognito("c-new") and eng.is_incognito("c-old")


def test_subagent_of_saved_chat_is_restored_on_undo(eng, db):
    _start(eng, db, "p", redact_pii=True)
    eng.adopt_subagent("p", "child")
    assert eng.is_incognito("child")
    eng.save_session("p")
    assert not eng.is_incognito("child")
    assert eng.undo_save("p")["ok"]
    assert eng.is_incognito("child")


def test_pending_burn_cannot_be_saved(eng, db):
    _start(eng, db, "pb")
    leases = eng._read_leases()
    leases["pb"]["pending_burn"] = True
    eng._write_leases(leases)
    res = eng.save_session("pb")
    assert res["ok"] is False and "deleted" in res["error"]
    assert eng.is_incognito("pb")


def test_save_rejects_non_incognito_and_bad_ids(eng):
    assert eng.save_session("never-incognito")["ok"] is False
    assert eng.save_session("../etc/passwd")["ok"] is False
    assert eng.undo_save("never-incognito")["ok"] is False


def test_double_save_is_refused_and_undo_is_single_use(eng, db):
    _start(eng, db, "d1")
    assert eng.save_session("d1")["ok"]
    assert eng.save_session("d1")["ok"] is False
    assert eng.undo_save("d1")["ok"]
    assert eng.undo_save("d1")["ok"] is False
    assert eng.is_incognito("d1")


# --- the undo window keeps the chat clean ---------------------------------------------------------


def test_memory_and_skills_stay_blocked_while_undo_is_available(eng, db, clock):
    _start(eng, db, "g1")
    eng.save_session("g1")
    for tool in ("memory", "skill_manage"):
        verdict = eng.evaluate_tool_guard("g1", tool, {"action": "add", "content": "x"})
        assert verdict and verdict["action"] == "block" and "Undo" in verdict["message"]
    clock["now"] += 11 * 60
    assert eng.evaluate_tool_guard("g1", "memory", {"action": "add", "content": "x"}) is None


def test_masking_continues_after_save_until_undo_window_ends(isolated_hermes_env, db, monkeypatch, clock):
    install_fake_hermes_middleware(monkeypatch)
    sim = SimHermes(plugin, isolated_hermes_env["home"])
    eng = plugin_engine.get_engine()
    _start(eng, db, "m1", redact_pii=True)
    sim.turn("m1", f"first {EMAIL}")
    eng.save_session("m1")
    sim.turn("m1", f"second {EMAIL}")
    assert all(EMAIL not in s for s in sim.sent)
    assert "[EMAIL_1]" in sim.sent[-1]
    assert scan_files(isolated_hermes_env["home"], [EMAIL]) == []
    clock["now"] += 11 * 60
    assert not eng.masking_active("m1")  # saved for good: a normal chat again


# --- surfaces -------------------------------------------------------------------------------------


def test_rest_rpc_and_slash_save_and_undo(eng, db):
    ctx = SimCtx()
    plugin.register(ctx)
    _start(eng, db, "r1")
    res = plugin_api.save_session({"session_id": "r1"})
    assert res["ok"] and res["saved"]["session_id"] == "r1" and res["incognito"] is False
    assert plugin_api.get_status(session_id="r1")["saved"]["undo_remaining_seconds"] > 0
    res = plugin_api.undo_save({"session_id": "r1"})
    assert res["ok"] and res["incognito"] is True and res["saved"] is None
    assert plugin_api.save_session({})["ok"] is False

    res = ctx.rpcs["save"]({"session_id": "r1"})
    assert res["ok"] and not eng.is_incognito("r1")
    res = ctx.rpcs["undo"]({"session_id": "r1"})
    assert res["ok"] and eng.is_incognito("r1")

    out = ctx.commands["incognito"]("save confirm", session_id="r1")
    assert "saved to your history" in out and not eng.is_incognito("r1")
    out = ctx.commands["incognito"]("undo", session_id="r1")
    assert "Back in Incognito" in out and eng.is_incognito("r1")
    assert "already saved" in ctx.commands["incognito"]("save", session_id="not-incog")


def test_cli_save_asks_first(eng, db, monkeypatch, capsys):
    captured = {}

    class CliCtx(SimCtx):
        def register_cli_command(self, *, name, help, setup_fn, handler_fn, description=""):
            captured["handler"] = handler_fn
            captured["setup"] = setup_fn

    plugin.register(CliCtx())
    import argparse

    parser = argparse.ArgumentParser()
    captured["setup"](parser)
    _start(eng, db, "cli1")
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    assert captured["handler"](parser.parse_args(["save", "cli1"])) == 1
    assert eng.is_incognito("cli1")
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    assert captured["handler"](parser.parse_args(["save", "cli1"])) == 0
    assert not eng.is_incognito("cli1")
    assert captured["handler"](parser.parse_args(["undo", "cli1"])) == 0
    assert eng.is_incognito("cli1")
    capsys.readouterr()
    assert captured["handler"](parser.parse_args(["save", "cli1", "--yes", "--json"])) == 0
    assert json.loads(capsys.readouterr().out)["saved"]["session_id"] == "cli1"
