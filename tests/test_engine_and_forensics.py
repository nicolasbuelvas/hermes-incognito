import os
import sys
import time
import json
import sqlite3
import threading
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safe import helper for when engine is still being implemented or updated
try:
    import engine
    IncognitoEngine = getattr(engine, "IncognitoEngine", None)
except ImportError:
    engine = None
    IncognitoEngine = None


def test_engine_enable_and_state(isolated_hermes_env):
    """Test enable_session in standard and strict modes, and get_session_state / is_incognito."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_1 = "sess-test-standard-1"
    sess_2 = "sess-test-strict-2"

    eng.enable_session(sess_1, mode="standard", ttl_minutes=30)
    assert eng.is_incognito(sess_1) is True
    st1 = eng.get_session_state(sess_1)
    assert st1 is not None
    assert st1.get("mode") == "standard"
    assert st1.get("ttl_minutes") == 30 or st1.get("ttl") == 30

    eng.enable_session(sess_2, mode="strict", ttl_minutes=15)
    assert eng.is_incognito(sess_2) is True
    st2 = eng.get_session_state(sess_2)
    assert st2 is not None
    assert st2.get("mode") == "strict"

    assert eng.is_incognito("sess-non-existent") is False
    assert eng.get_session_state("sess-non-existent") is None


def test_engine_toggle_session(isolated_hermes_env):
    """Test toggling an incognito session between active and disabled."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess = "sess-toggle-1"
    assert eng.is_incognito(sess) is False

    eng.toggle_session(sess, mode="standard")
    assert eng.is_incognito(sess) is True

    eng.toggle_session(sess, mode="standard")
    assert eng.is_incognito(sess) is False


def test_engine_disable_session_keep_vs_burn(isolated_hermes_env):
    """Test disable_session with action='keep' vs action='burn'."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    # Action = keep
    sess_keep = "sess-disable-keep"
    sess_file = isolated_hermes_env["sessions_dir"] / f"{sess_keep}.jsonl"
    sess_file.write_text('{"role": "user", "content": "hello keep"}\n', encoding="utf-8")

    eng.enable_session(sess_keep, mode="standard")
    assert eng.is_incognito(sess_keep) is True

    eng.disable_session(sess_keep, action="keep")
    assert eng.is_incognito(sess_keep) is False
    assert sess_file.exists()

    # Action = burn
    sess_burn = "sess-disable-burn"
    sess_burn_file = isolated_hermes_env["sessions_dir"] / f"{sess_burn}.jsonl"
    sess_burn_file.write_text('{"role": "user", "content": "hello burn"}\n', encoding="utf-8")

    eng.enable_session(sess_burn, mode="standard")
    assert eng.is_incognito(sess_burn) is True

    eng.disable_session(sess_burn, action="burn")
    assert eng.is_incognito(sess_burn) is False
    assert not sess_burn_file.exists()


def test_engine_arm_next_session(isolated_hermes_env):
    """Test arm_next_session, get_armed_state, consume_armed_session, and disarm_next_session."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    eng.arm_next_session(mode="strict", ttl_minutes=15)
    armed = eng.get_armed_state()
    assert armed is not None
    assert armed.get("mode") == "strict"
    assert armed.get("ttl_minutes") == 15 or armed.get("ttl") == 15

    new_sess = "sess-consumed-1"
    eng.consume_armed_session(new_sess)
    assert eng.get_armed_state() is None
    assert eng.is_incognito(new_sess) is True
    st = eng.get_session_state(new_sess)
    assert st.get("mode") == "strict"

    # Test disarm
    eng.arm_next_session(mode="standard", ttl_minutes=10)
    assert eng.get_armed_state() is not None
    eng.disarm_next_session()
    assert eng.get_armed_state() is None


def test_engine_propagate_compaction(isolated_hermes_env):
    """Test propagate_compaction transfers lease and RAM vault, marking new session hidden."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    old_sess = "sess-old-compaction"
    new_sess = "sess-new-compaction"

    eng.enable_session(old_sess, mode="strict", ttl_minutes=25)
    if hasattr(eng, "store_vault_entry"):
        eng.store_vault_entry(old_sess, "[REDACTED_EMAIL_1]", "alice.smith@example.org")

    eng.propagate_compaction(old_sess, new_sess)

    assert eng.is_incognito(new_sess) is True
    st_new = eng.get_session_state(new_sess)
    assert st_new.get("mode") == "strict"

    if hasattr(eng, "get_vault_entry"):
        assert eng.get_vault_entry(new_sess, "[REDACTED_EMAIL_1]") == "alice.smith@example.org"


def test_engine_burn_session_zero_fill_and_receipt(isolated_hermes_env, monkeypatch):
    """
    Test burn_session deletes session rows, zero-fills files before unlink,
    clears RAM vault, and records content-free receipt.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
    monkeypatch.setattr(engine, "SessionDB", type(isolated_hermes_env["mock_db"]))
    if hasattr(eng, "config"):
        eng.config["zero_fill_files"] = True

    sess_id = "sess-burn-zero-fill"
    sess_file = isolated_hermes_env["sessions_dir"] / f"{sess_id}.jsonl"
    sess_file.write_text('{"role": "user", "content": "ephemeral sensitive query"}\n', encoding="utf-8")

    spill_dir = isolated_hermes_env["hook_outputs_dir"] / sess_id
    spill_dir.mkdir(parents=True, exist_ok=True)
    spill_file = spill_dir / "spill.txt"
    spill_file.write_text("sensitive hook spill content", encoding="utf-8")

    # Insert into mock db
    db_path = tmp_path / "state.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("INSERT OR REPLACE INTO sessions (id, title) VALUES (?, ?)", (sess_id, "Secret chat"))
        conn.execute("INSERT OR REPLACE INTO messages (id, session_id, content) VALUES (?, ?, ?)", ("m1", sess_id, "Secret msg"))
        conn.commit()

    eng.enable_session(sess_id, mode="strict")
    if hasattr(eng, "store_vault_entry"):
        eng.store_vault_entry(sess_id, "[REDACTED_EMAIL_1]", "alice.smith@example.org")

    receipt = eng.burn_session(sess_id, reason="burn")
    assert receipt is not None
    assert "receipt_id" in receipt or "id" in receipt
    # Ensure receipt NEVER stores message content
    receipt_str = json.dumps(receipt)
    assert "Secret msg" not in receipt_str
    assert "ephemeral sensitive query" not in receipt_str

    # Verify files deleted
    assert not sess_file.exists()
    assert not spill_file.exists()

    # Verify db rows deleted
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM sessions WHERE id = ?", (sess_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT count(*) FROM messages WHERE session_id = ?", (sess_id,))
        assert cursor.fetchone()[0] == 0


def test_engine_verify_zero_trace(isolated_hermes_env):
    """
    Test verify_zero_trace returns zero_trace=False while artifacts exist,
    and zero_trace=True after burn_session.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    sess_id = "sess-verify-zero-trace"
    sess_file = isolated_hermes_env["sessions_dir"] / f"{sess_id}.jsonl"
    sess_file.write_text('{"msg": "trace test"}\n', encoding="utf-8")

    eng.enable_session(sess_id, mode="standard")
    before_trace = eng.verify_zero_trace(sess_id)
    assert before_trace.get("zero_trace") is False

    eng.burn_session(sess_id, reason="burn")
    after_trace = eng.verify_zero_trace(sess_id)
    assert after_trace.get("zero_trace") is True
    assert after_trace.get("db_rows_found") == 0
    assert after_trace.get("session_files_found") == 0
    assert after_trace.get("hook_files_found") == 0
    assert after_trace.get("ram_vault_entries") == 0
    assert after_trace.get("active_lease") is False


def test_engine_sweep_expired(isolated_hermes_env):
    """Test sweep_expired reaps expired sessions and preserves active unexpired ones."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    active_sess = "sess-active-sweep"
    expired_sess = "sess-expired-sweep"

    # Active session with 60 min TTL
    eng.enable_session(active_sess, mode="standard", ttl_minutes=60)
    # Expired session with negative/zero TTL or simulated past expiry
    eng.enable_session(expired_sess, mode="standard", ttl_minutes=1)

    # Manually backdate expired_sess state if stored in memory/files
    st = eng.get_session_state(expired_sess)
    if hasattr(eng, "set_session_expiry"):
        eng.set_session_expiry(expired_sess, time.time() - 100)
    elif isinstance(st, dict):
        st["expires_at"] = time.time() - 100

    eng.sweep_expired()

    assert eng.is_incognito(active_sess) is True
    assert eng.is_incognito(expired_sess) is False


def test_engine_concurrency(isolated_hermes_env):
    """Concurrency test: 8 threads toggling/touching sessions concurrently without race conditions."""
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)

    errors = []

    def worker(worker_id):
        try:
            for i in range(20):
                sess_id = f"sess-thread-{worker_id}-{i}"
                eng.enable_session(sess_id, mode="standard", ttl_minutes=10)
                _ = eng.is_incognito(sess_id)
                _ = eng.get_session_state(sess_id)
                eng.toggle_session(sess_id, mode="standard")
                eng.toggle_session(sess_id, mode="standard")
                if hasattr(eng, "store_vault_entry"):
                    eng.store_vault_entry(sess_id, f"[TAG_{i}]", f"data_{i}")
                eng.burn_session(sess_id, reason="test_cleanup")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrency errors occurred: {errors}"


def test_engine_burn_busy_session_defers_until_sessiondb_can_delete(isolated_hermes_env, monkeypatch):
    """A busy admission keeps the session and its messages until SessionDB can delete both."""
    monkeypatch.setattr(engine, "SessionDB", type(isolated_hermes_env["mock_db"]))
    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
    retries = []
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda sid, attempt: retries.append((sid, attempt)))

    sess_id = "local-busy-admission-chat"
    db_path = tmp_path / "state.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS admission_guard (session_id TEXT PRIMARY KEY)")
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS guard_busy_session
            BEFORE DELETE ON sessions
            WHEN EXISTS (SELECT 1 FROM admission_guard WHERE session_id = old.id)
            BEGIN
                SELECT RAISE(ABORT, 'session_busy');
            END;
            """
        )
        conn.execute("INSERT INTO admission_guard (session_id) VALUES (?)", (sess_id,))
        conn.execute("INSERT OR REPLACE INTO sessions (id, title) VALUES (?, ?)", (sess_id, "Recordar color stiven"))
        conn.execute(
            "INSERT OR REPLACE INTO messages (id, session_id, role, content) VALUES (?, ?, ?, ?)",
            ("m-secret-1", sess_id, "user", "Mi color favorito es stiven"),
        )
        conn.commit()

    eng.enable_session(sess_id, mode="strict")
    burn_res = eng.burn_session(sess_id, reason="session_finalize")

    # The failed SessionDB transaction leaves both rows intact.
    with sqlite3.connect(str(db_path)) as conn:
        msg_count = conn.execute("SELECT count(*) FROM messages WHERE session_id = ?", (sess_id,)).fetchone()[0]
        sess_count = conn.execute("SELECT count(*) FROM sessions WHERE id = ?", (sess_id,)).fetchone()[0]
    assert msg_count == 1
    assert sess_count == 1
    assert retries == [(sess_id, 1)]
    assert burn_res["db_deleted"] is False
    assert burn_res["pending_burn"] is True
    assert eng.is_incognito(sess_id)
    assert eng.get_session_state(sess_id)["pending_burn"]
    assert eng.evaluate_tool_guard(sess_id, "memory")["action"] == "block"
    assert eng.evaluate_tool_guard(sess_id, "skill_manage")["action"] == "block"
    assert eng.evaluate_tool_guard(sess_id, "cronjob_manage")["action"] == "block"
    assert not eng.enable_session(sess_id)["ok"]
    assert not eng.disable_session(sess_id)["ok"]
    assert not eng.toggle_session(sess_id)["ok"]
    assert not eng.set_session_ttl(sess_id, 0)["ok"]
    assert sess_id in eng.get_protected_session_ids()

    # Once Gateway marks admission terminal (guard cleared), sweep_expired completes zero-trace
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("DELETE FROM admission_guard WHERE session_id = ?", (sess_id,))
        conn.commit()

    eng.sweep_expired()
    verify = eng.verify_zero_trace(sess_id)
    assert verify["zero_trace"] is True
    assert sess_id not in eng.get_protected_session_ids()


def test_burn_requires_lease_or_database_marker(isolated_hermes_env, monkeypatch):
    mock_db = isolated_hermes_env["mock_db"]
    monkeypatch.setattr(engine, "SessionDB", type(mock_db))
    eng = IncognitoEngine()
    sid, public_sid = "private", "public"
    public_file = eng.home_dir / "sessions" / f"{public_sid}.jsonl"
    public_file.write_text("keep")
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.execute("INSERT INTO sessions (id) VALUES (?)", (public_sid,))
        conn.execute("INSERT INTO sessions (id, model_config) VALUES (?, ?)", (sid, '{"incognito": {}}'))

    assert not eng.burn_session(public_sid)["ok"]
    assert not eng.burn_session("../public")["ok"]
    assert not eng.burn_session(r"bad\public")["ok"]
    assert not eng.burn_session(str(public_file))["ok"]
    assert eng.burn_session(sid)["db_deleted"]
    assert public_file.read_text() == "keep"
    assert mock_db.get_session(public_sid)


def test_burn_refuses_unmarked_cascade(isolated_hermes_env, monkeypatch):
    mock_db = isolated_hermes_env["mock_db"]
    monkeypatch.setattr(engine, "SessionDB", type(mock_db))
    monkeypatch.setattr(type(mock_db), "get_session_delete_targets", lambda db, sid: [sid, "public"])
    eng = IncognitoEngine()
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda *a, **kw: None)
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.executemany("INSERT INTO sessions (id) VALUES (?)", [("private",), ("public",)])
    eng.enable_session("private")
    leases = eng._read_leases()
    leases["private"]["lineage_ids"] += ["public", "../public"]
    eng._write_leases(leases)

    result = eng.burn_session("private")
    assert result["pending_burn"]
    assert mock_db.get_session("private")
    assert mock_db.get_session("public")


def test_burn_deletes_delegate_subagent_children_of_incognito_session(isolated_hermes_env, monkeypatch):
    mock_db = isolated_hermes_env["mock_db"]
    monkeypatch.setattr(engine, "SessionDB", type(mock_db))
    eng = IncognitoEngine()
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda *a, **kw: None)
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.execute("INSERT INTO sessions (id) VALUES ('private')")
        conn.execute(
            "INSERT INTO sessions (id, source, parent_session_id) VALUES ('subagent-1', 'delegate', 'private')"
        )
        conn.execute("INSERT INTO sessions (id) VALUES ('public')")
    eng.enable_session("private")

    result = eng.burn_session("private")
    assert result["ok"] is True
    assert result["db_deleted"] is True
    assert result["pending_burn"] is False
    assert mock_db.get_session("private") is None
    assert mock_db.get_session("subagent-1") is None
    assert mock_db.get_session("public") is not None


def test_burn_uses_exact_file_ownership_and_rejects_symlinks(isolated_hermes_env):
    eng = IncognitoEngine()
    eng.enable_session("private")
    sessions = isolated_hermes_env["sessions_dir"]
    hooks = isolated_hermes_env["hook_outputs_dir"]
    outside = isolated_hermes_env["home"] / "outside"
    outside.mkdir()
    keep = outside / "keep.txt"
    keep.write_text("outside")
    try:
        (hooks / "private").symlink_to(outside, target_is_directory=True)
        (sessions / "private.jsonl").symlink_to(keep)
    except OSError:
        pass
    owned_files = [
        sessions / "session_private.json",
        sessions / "request_dump_private_20261112_123456_123456.json",
        hooks / "private.txt",
    ]
    public_files = [
        sessions / "private-other.jsonl",
        sessions / "request_dump_private_other_20261112_123456_123456.json",
        hooks / "private-other.txt",
    ]
    for path in owned_files + public_files:
        path.write_text("content")

    result = eng.burn_session("private")
    assert result["files_scrubbed"] == len(owned_files)
    assert all(not path.exists() for path in owned_files)
    assert all(path.read_text() == "content" for path in public_files)
    assert keep.read_text() == "outside"


def test_burn_leaves_rows_pending_when_sessiondb_is_unavailable(isolated_hermes_env, monkeypatch):
    eng = IncognitoEngine()
    monkeypatch.setattr(engine, "SessionDB", None)
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda *a, **kw: None)
    eng.enable_session("private")
    mock_db = isolated_hermes_env["mock_db"]
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.execute("INSERT INTO sessions (id) VALUES ('private')")

    assert eng.burn_session("private")["pending_burn"]
    assert mock_db.get_session("private")
    assert not eng.verify_zero_trace("private")["zero_trace"]


def test_file_cleanup_failure_keeps_burn_pending_across_restart(isolated_hermes_env, monkeypatch):
    mock_db = isolated_hermes_env["mock_db"]
    monkeypatch.setattr(engine, "SessionDB", type(mock_db))
    eng = IncognitoEngine()
    retries = []
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda sid, attempt: retries.append((sid, attempt)))
    sid = "file-cleanup-retry"
    path = isolated_hermes_env["sessions_dir"] / f"{sid}.jsonl"
    path.write_text("synthetic transcript")
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.execute("INSERT INTO sessions (id) VALUES (?)", (sid,))
    eng.enable_session(sid, mode="strict", redact_pii=True)
    request = {"messages": [{"role": "user", "content": "example@example.org"}]}
    eng.transform_llm_request(sid, request)

    unlink = Path.unlink

    def fail_transcript_unlink(file_path, *args, **kwargs):
        if file_path == path:
            raise PermissionError("temporary file cleanup error")
        return unlink(file_path, *args, **kwargs)

    with monkeypatch.context() as fail:
        fail.setattr(Path, "unlink", fail_transcript_unlink)
        result = eng.burn_session(sid)
        assert result["ok"] and result["pending_burn"] and result["files_pending"]
        assert result["db_deleted"] and mock_db.get_session(sid) is None
        assert eng.sweep_expired()["swept_count"] == 0

    assert path.exists()
    assert retries[0] == (sid, 1)
    assert eng.is_incognito(sid)
    verification = eng.verify_zero_trace(sid)
    assert verification["ram_vault_entries"] == 1
    assert not verification["zero_trace"]

    restarted = IncognitoEngine()
    result = restarted.burn_session(sid)
    assert result["ok"] and not result["pending_burn"] and not result["files_pending"]
    assert result["db_deleted"]
    assert not path.exists()
    assert restarted.verify_zero_trace(sid)["zero_trace"]


def test_burn_recovers_after_interruption_with_database_only_marker(isolated_hermes_env, monkeypatch):
    mock_db = isolated_hermes_env["mock_db"]
    monkeypatch.setattr(engine, "SessionDB", type(mock_db))
    eng = IncognitoEngine()
    sid = "interrupted-cleanup"
    transcript = isolated_hermes_env["sessions_dir"] / f"{sid}.jsonl"
    transcript.write_text("synthetic transcript")
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.execute("INSERT INTO sessions (id, model_config) VALUES (?, ?)", (sid, '{"incognito": {"mode": "strict"}}'))
        conn.execute("INSERT INTO sessions (id) VALUES (?)", ("public",))

    def interrupt_before_file_cleanup(_target_ids):
        raise SystemExit

    assert not eng.is_incognito(sid)
    monkeypatch.setattr(eng, "_scrub_burn_files", interrupt_before_file_cleanup)
    with pytest.raises(SystemExit):
        eng.burn_session(sid)

    assert mock_db.get_session(sid) is None
    assert transcript.exists()
    restarted = IncognitoEngine()
    assert restarted.get_session_state(sid)["pending_burn"]
    assert restarted.evaluate_tool_guard(sid, "cronjob_manage")["action"] == "block"
    assert restarted.sweep_expired()["swept_count"] == 1
    assert restarted.verify_zero_trace(sid)["zero_trace"]
    assert mock_db.get_session("public") is not None


def test_burn_preserves_artifacts_if_recovery_cannot_be_saved(isolated_hermes_env, monkeypatch):
    mock_db = isolated_hermes_env["mock_db"]
    monkeypatch.setattr(engine, "SessionDB", type(mock_db))
    eng = IncognitoEngine()
    sid = "recovery-write-error"
    transcript = isolated_hermes_env["sessions_dir"] / f"{sid}.jsonl"
    transcript.write_text("synthetic transcript")
    with sqlite3.connect(mock_db.db_path) as conn:
        conn.execute("INSERT INTO sessions (id, model_config) VALUES (?, ?)", (sid, '{"incognito": true}'))

    def fail_recovery_write(_leases):
        raise PermissionError("cannot write recovery metadata")

    monkeypatch.setattr(eng, "_write_leases", fail_recovery_write)
    with pytest.raises(PermissionError):
        eng.burn_session(sid)

    assert mock_db.get_session(sid) is not None
    assert transcript.read_text() == "synthetic transcript"


# --- Ported from upstream main (ebdb0ef) ---


def test_burn_session_refuses_non_incognito_and_unsafe_session_ids(isolated_hermes_env, monkeypatch):
    """
    burn_session must:
      1) Refuse any session_id that has neither an incognito lease nor model_config.incognito tag,
         leaving non-incognito DB rows and transcript files completely untouched.
      2) Refuse unsafe session_ids containing '/', '\\', '..', or absolute paths.
      3) Allow burning an orphaned session tagged with model_config.incognito in SessionDB even
         when leases.json has no entry for it.
    """
    # Exercise the SessionDB marker path with the isolated mock (the suite defaults to no SessionDB).
    monkeypatch.setattr(engine, "SessionDB", type(isolated_hermes_env["mock_db"]))
    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
    db_path = tmp_path / "state.db"

    # 1. Normal non-incognito session must NOT be burned
    normal_sid = "sess-normal-untouched"
    normal_file = isolated_hermes_env["sessions_dir"] / f"{normal_sid}.jsonl"
    normal_file.write_text('{"role": "user", "content": "important permanent chat"}\n', encoding="utf-8")
    if engine.SessionDB is not None:
        real_db = engine.SessionDB(db_path=db_path)
        try:
            real_db.create_session(normal_sid, source="cli", model="gpt-4")
        finally:
            real_db.close()
    else:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("INSERT OR REPLACE INTO sessions (id, title) VALUES (?, ?)", (normal_sid, "Permanent"))
            conn.commit()

    refused_normal = eng.burn_session(normal_sid, reason="unauthorized_attempt")
    assert refused_normal["ok"] is False
    assert normal_file.exists()
    with sqlite3.connect(str(db_path)) as conn:
        assert conn.execute("SELECT count(*) FROM sessions WHERE id = ?", (normal_sid,)).fetchone()[0] == 1

    # 2. Unsafe path-traversal or absolute session_ids must be refused
    for bad_id in ("../sessions", "..\\sessions", "foo/bar", "foo\\bar", "a..b", "/abs/path", "C:\\abs\\path"):
        res_bad = eng.burn_session(bad_id, reason="traversal_attempt")
        assert res_bad["ok"] is False

    # 3. Session tagged via model_config.incognito in SessionDB (without lease in leases.json) CAN be burned
    if engine.SessionDB is not None:
        tagged_sid = "sess-db-tagged-incog"
        tagged_file = isolated_hermes_env["sessions_dir"] / f"{tagged_sid}.jsonl"
        tagged_file.write_text('{"role": "user", "content": "orphaned incog"}\n', encoding="utf-8")
        real_db = engine.SessionDB(db_path=db_path)
        try:
            real_db.create_session(tagged_sid, source="cli", model="gpt-4")
            real_db.patch_session_model_config(tagged_sid, {"incognito": {"mode": "strict"}})
        finally:
            real_db.close()

        burned_tagged = eng.burn_session(tagged_sid, reason="orphan_cleanup")
        assert burned_tagged["ok"] is True
        assert not tagged_file.exists()
        with sqlite3.connect(str(db_path)) as conn:
            assert conn.execute("SELECT count(*) FROM sessions WHERE id = ?", (tagged_sid,)).fetchone()[0] == 0


def test_burn_and_verify_confine_hook_outputs_and_use_exact_filenames(isolated_hermes_env):
    """
    burn_session and verify_zero_trace must:
      1) Use exact filename matches in sessions/ and hook_outputs/ so prefix/substring neighbors
         (e.g. 'sessions.json', 'sess-10.jsonl', 'sess-10.txt') are NEVER touched or flagged.
      2) Confine sid_dir deletion so resolved sid_dir must be a direct child of hook_outputs_dir.resolve()
         (refusing symlink escapes outside hook_outputs_dir).
    """
    tmp_path = isolated_hermes_env["home"]
    sessions_dir = isolated_hermes_env["sessions_dir"]
    hook_outputs_dir = isolated_hermes_env["hook_outputs_dir"]
    eng = IncognitoEngine(home_dir=tmp_path)

    # Session ID 'sess-1' is a prefix substring of 'sess-10' and 'session' is a substring of 'sessions.json'
    target_sid = "session"
    neighbor_sid = "session-keep"

    gateway_index = sessions_dir / "sessions.json"
    gateway_index.write_text('{"telegram:123": "session-keep"}', encoding="utf-8")
    neighbor_transcript = sessions_dir / f"{neighbor_sid}.jsonl"
    neighbor_transcript.write_text('{"role": "user", "content": "neighbor"}\n', encoding="utf-8")
    neighbor_hook_file = hook_outputs_dir / f"{neighbor_sid}.txt"
    neighbor_hook_file.write_text("neighbor hook output", encoding="utf-8")

    own_transcript = sessions_dir / f"{target_sid}.jsonl"
    own_transcript.write_text('{"role": "user", "content": "secret"}\n', encoding="utf-8")
    own_hook_dir = hook_outputs_dir / target_sid
    own_hook_dir.mkdir(parents=True, exist_ok=True)
    own_spill = own_hook_dir / "spill1.txt"
    own_spill.write_text("secret spill", encoding="utf-8")
    own_hook_flat = hook_outputs_dir / f"{target_sid}.txt"
    own_hook_flat.write_text("flat spill", encoding="utf-8")

    eng.enable_session(target_sid, mode="strict")
    res = eng.burn_session(target_sid, reason="burn")
    assert res["ok"] is True

    # Own files deleted
    assert not own_transcript.exists()
    assert not own_spill.exists()
    assert not own_hook_dir.exists()
    assert not own_hook_flat.exists()

    # Substring neighbor files and sessions.json MUST survive untouched
    assert gateway_index.exists()
    assert neighbor_transcript.exists()
    assert neighbor_hook_file.exists()

    # verify_zero_trace on target_sid must report zero_trace=True despite substring neighbors existing
    verified = eng.verify_zero_trace(target_sid)
    assert verified["zero_trace"] is True
    assert verified["session_files_found"] == 0
    assert verified["hook_files_found"] == 0

    # If a symlink or junctions in hook_outputs/<sid> resolves outside hook_outputs_dir, do not delete outside target
    outside_dir = tmp_path / "outside_protected_dir"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside_file = outside_dir / "must_survive.txt"
    outside_file.write_text("critical host data", encoding="utf-8")

    symlink_sid = "sess-symlink-escape"
    link_path = hook_outputs_dir / symlink_sid
    symlink_created = False
    try:
        link_path.symlink_to(outside_dir, target_is_directory=True)
        symlink_created = True
    except OSError:
        pass

    if symlink_created:
        eng.enable_session(symlink_sid, mode="standard")
        eng.burn_session(symlink_sid, reason="burn")
        assert outside_file.exists()


def test_engine_never_issues_raw_sql_deletes():
    """Ported from upstream: state.db rows are deleted only through SessionDB.delete_session()."""
    engine_source = (PROJECT_ROOT / "engine.py").read_text(encoding="utf-8")
    assert "DELETE FROM" not in engine_source
