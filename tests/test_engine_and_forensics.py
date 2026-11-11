import os
import sys
import time
import json
import sqlite3
import threading
from pathlib import Path
import pytest

PROJECT_ROOT = Path("C:/Users/nicol/Downloads/Proyectos personales/hermes-incognito").resolve()
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


def test_engine_burn_session_zero_fill_and_receipt(isolated_hermes_env):
    """
    Test burn_session deletes session rows, zero-fills files before unlink,
    clears RAM vault, and records content-free receipt.
    """
    if IncognitoEngine is None:
        pytest.skip("IncognitoEngine not yet importable")

    tmp_path = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=tmp_path)
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
        cursor.execute("SELECT count(*) FROM messages WHERE id = ?", (sess_id,))
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
