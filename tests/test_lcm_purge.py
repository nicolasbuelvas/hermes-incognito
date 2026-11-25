"""Gate 3b: burning an incognito session must purge its rows from the LCM store.

lcm.db (hermes-home root, owned by the hermes-lcm-x plugin) indexes live turns, so a
burned session otherwise keeps raw, FTS-searchable rows in a store the local burn never
touches. ``purge_lcm_store`` is best-effort with log-only failures (a busy or missing
lcm.db must never block the local burn) and register() wires it into on_burn_complete
alongside the RetainDB purge, covering every burned target id including cascaded ancestors.
"""
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest  # noqa: F401  (parity with sibling test modules)

import engine as engine_mod
from engine import IncognitoEngine

_SID = "sid-lcm-purge-777"

# Load the plugin's own __init__ (its register/_make_burn_callback live there) the same
# way the host loader does, so the wiring test exercises the real callback factory.
_pspec = importlib.util.spec_from_file_location(
    "incognito_plugin_init_for_test", Path(__file__).resolve().parent.parent / "__init__.py")
_plugin_module = importlib.util.module_from_spec(_pspec)
_pspec.loader.exec_module(_plugin_module)
_LCM_SCHEMA = """
CREATE TABLE messages (
    store_id INTEGER PRIMARY KEY, session_id TEXT, source TEXT, conversation_id TEXT,
    role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT,
    timestamp REAL, token_estimate INTEGER, pinned INTEGER, ingested_at REAL,
    observed_at REAL, observed_at_source TEXT, sender_id TEXT, sender_source TEXT);
CREATE VIRTUAL TABLE messages_fts USING fts5(content, content='messages', content_rowid='store_id');
CREATE VIRTUAL TABLE messages_fts_stem USING fts5(content, content='messages', content_rowid='store_id', tokenize='porter unicode61');
CREATE TABLE summary_nodes (
    node_id INTEGER PRIMARY KEY, session_id TEXT, depth INTEGER, summary TEXT,
    token_count INTEGER, source_token_count INTEGER, source_ids TEXT, source_type TEXT,
    created_at TEXT, earliest_at TEXT, latest_at TEXT, expand_hint TEXT);
CREATE TABLE summary_node_provenance (node_id INTEGER, escalation_level INTEGER, model TEXT, created_at TEXT);
CREATE TABLE message_relations (
    relation_id INTEGER PRIMARY KEY, store_id INTEGER, kind TEXT,
    related_store_id INTEGER, ordinal INTEGER, observed_at REAL, created_at REAL);
CREATE TABLE host_uid_bindings (
    store_id INTEGER, uid TEXT, lineage_key TEXT, kind TEXT, binding_version INTEGER,
    proof_kind TEXT, created_at REAL, first_check REAL, disagree_seen INTEGER);
CREATE TABLE lcm_rollups (
    rollup_id INTEGER PRIMARY KEY, period_kind TEXT, period_start REAL, scope TEXT,
    summary TEXT, token_count INTEGER, status TEXT, built_at REAL,
    source_fingerprint TEXT, error TEXT, generation INTEGER,
    lease_expires_at REAL, lease_nonce TEXT, failed_at REAL);
CREATE TABLE lcm_rollup_sources (rollup_id INTEGER, node_id INTEGER);
CREATE TABLE lcm_rollup_invalidations (
    event_id INTEGER PRIMARY KEY, node_id INTEGER, scope TEXT, covered_start REAL,
    covered_end REAL, next_day INTEGER, operation TEXT, created_at REAL);
CREATE TABLE lcm_chunk_meta (
    chunk_id INTEGER PRIMARY KEY, identity_hash TEXT, store_id INTEGER, chunk_index INTEGER,
    char_start INTEGER, char_end INTEGER, token_estimate INTEGER, embedded_at REAL, archived INTEGER);
CREATE TABLE lcm_chunk_vectors (chunk_id INTEGER, identity_hash TEXT, vec BLOB);
CREATE TABLE lcm_chunk_binary (chunk_id INTEGER, identity_hash TEXT, bits BLOB);
CREATE TABLE lcm_embedding_vectors (embedded_id TEXT, identity_hash TEXT, vec BLOB);
CREATE TABLE lcm_embedding_binary (embedded_id TEXT, identity_hash TEXT, bits BLOB);
CREATE TABLE lcm_lifecycle_state (
    conversation_id TEXT PRIMARY KEY, current_session_id TEXT, last_finalized_session_id TEXT,
    current_frontier_store_id INTEGER, last_finalized_frontier_store_id INTEGER,
    debt_kind TEXT, debt_size_estimate INTEGER, current_bound_at REAL, last_finalized_at REAL,
    debt_updated_at REAL, last_rollover_at REAL, last_reset_at REAL, updated_at REAL);
"""


def _make_lcm_db(path, *, session_id: str = _SID) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.executescript(_LCM_SCHEMA)
    con.execute(
        "INSERT INTO messages (store_id, session_id, role, content) VALUES (1, ?, 'user', 'lcm-gate-probe-1')",
        (session_id,))
    con.execute(
        "INSERT INTO messages (store_id, session_id, role, content) VALUES (2, ?, 'assistant', 'lcm-gate-reply-1')",
        (session_id,))
    con.execute(
        "INSERT INTO messages (store_id, session_id, role, content) VALUES (3, 'other-session', 'user', 'lcm-other-row')")
    con.execute("INSERT INTO messages_fts(rowid, content) VALUES (1, 'lcm-gate-probe-1')")
    con.execute("INSERT INTO messages_fts(rowid, content) VALUES (2, 'lcm-gate-reply-1')")
    con.execute("INSERT INTO messages_fts(rowid, content) VALUES (3, 'lcm-other-row')")
    con.execute(
        "INSERT INTO summary_nodes (node_id, session_id, summary) VALUES (10, ?, 'lcm-summary')", (session_id,))
    con.execute("INSERT INTO summary_node_provenance (node_id, model) VALUES (10, 'test-model')")
    con.execute(
        "INSERT INTO message_relations (relation_id, store_id, kind, related_store_id) VALUES (1, 1, 't', 2)")
    con.execute("INSERT INTO host_uid_bindings (store_id, uid) VALUES (1, 'uid-1')")
    con.execute(
        "INSERT INTO lcm_chunk_meta (chunk_id, identity_hash, store_id) VALUES (50, 'h', 1)")
    con.execute("INSERT INTO lcm_chunk_vectors (chunk_id, identity_hash) VALUES (50, 'h')")
    con.execute(
        "INSERT INTO lcm_rollups (rollup_id, period_kind, scope, summary) VALUES (1, 'h', 'c', 'lcm-rollup')")
    con.execute("INSERT INTO lcm_rollup_sources (rollup_id, node_id) VALUES (1, 10)")
    con.execute("INSERT INTO lcm_embedding_vectors (embedded_id, identity_hash) VALUES ('1', 'h')")
    con.execute(
        "INSERT INTO lcm_lifecycle_state (conversation_id, current_session_id, current_frontier_store_id) "
        "VALUES ('conv-1', ?, 2)", (session_id,))
    con.commit()
    return con


def test_purge_lcm_store_removes_session_rows(isolated_hermes_env):
    home = isolated_hermes_env["home"]
    con = _make_lcm_db(home / "lcm.db")
    eng = IncognitoEngine(home_dir=home)
    result = eng.purge_lcm_store(_SID)
    assert result.get("error") in (None, ""), result
    # the burned session is gone from every table; the other-session row survives (checked below)
    assert con.execute("SELECT COUNT(*) FROM messages WHERE session_id = ?", (_SID,)).fetchone()[0] == 0
    for table in ("summary_nodes", "summary_node_provenance", "message_relations",
                  "host_uid_bindings", "lcm_chunk_meta", "lcm_chunk_vectors",
                  "lcm_rollup_sources", "lcm_embedding_vectors"):
        n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert n == 0, f"{table} still has rows: {n}"
    # rollup with all sources deleted is dropped too
    assert con.execute("SELECT COUNT(*) FROM lcm_rollups").fetchone()[0] == 0
    # FTS mirrors are rebuilt: the probe term is gone, other-session row untouched
    assert con.execute("SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'probe'").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'other'").fetchone()[0] == 1
    # other-session raw row untouched
    assert con.execute("SELECT COUNT(*) FROM messages WHERE session_id = 'other-session'").fetchone()[0] == 1
    # lifecycle pointer cleared
    row = con.execute("SELECT current_session_id, current_frontier_store_id FROM lcm_lifecycle_state WHERE conversation_id = 'conv-1'").fetchone()
    assert row == (None, None)
    assert result.get("purged_messages") == 2 and result.get("purged_summaries") == 1
    con.close()


def test_purge_lcm_store_missing_db_skips(isolated_hermes_env):
    home = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=home)
    result = eng.purge_lcm_store(_SID)
    assert "skipped" in result and result.get("error") in (None, "")


def test_purge_lcm_store_db_error_reports_without_raising(isolated_hermes_env):
    home = isolated_hermes_env["home"]
    (home / "lcm.db").write_bytes(b"not a sqlite database")
    eng = IncognitoEngine(home_dir=home)
    result = eng.purge_lcm_store(_SID)
    assert result.get("error"), f"expected an error, got {result}"


def test_purge_lcm_store_empty_session_noop(isolated_hermes_env):
    home = isolated_hermes_env["home"]
    con = _make_lcm_db(home / "lcm.db", session_id="some-other-session")
    eng = IncognitoEngine(home_dir=home)
    result = eng.purge_lcm_store(_SID)
    assert result.get("error") in (None, "")
    assert result.get("purged_messages") == 0
    # the other session's rows survive (all three fixture rows are that session's)
    assert con.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 3
    con.close()


def test_on_burn_complete_wires_lcm_purge(isolated_hermes_env, monkeypatch):
    """register()'s callback (the real wiring) must purge BOTH external stores."""
    home = isolated_hermes_env["home"]
    eng = IncognitoEngine(home_dir=home)
    calls = []

    monkeypatch.setattr(eng, "purge_memory_store", lambda sid: calls.append(("retaindb", sid)) or {})
    monkeypatch.setattr(eng, "purge_lcm_store", lambda sid: calls.append(("lcm", sid)) or {})
    emitted = []
    callback = _plugin_module._make_burn_callback(eng, lambda sid, topic, payload: emitted.append((sid, topic)))
    callback(_SID)
    assert ("retaindb", _SID) in calls
    assert ("lcm", _SID) in calls
    assert (_SID, "state.changed") in emitted
