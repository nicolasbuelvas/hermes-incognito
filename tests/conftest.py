import json
import sys
import sqlite3
import pytest
from pathlib import Path

# Setup paths. The suite never adds a local Hermes install to sys.path: tests must not pick up
# a real SessionDB, config, or plugin storage from ~/.hermes, so results stay deterministic.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_ENGINE_MODULES = ("engine", "hermes_plugin_incognito_test.engine")


class MockSessionDB:
    """Mock SessionDB fallback if hermes_state is not available."""
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    created_at REAL,
                    updated_at REAL,
                    model_config TEXT,
                    hidden INTEGER DEFAULT 0,
                    source TEXT,
                    parent_session_id TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    role TEXT,
                    content TEXT,
                    created_at REAL
                )
            """)
            conn.commit()

    def close(self):
        pass

    def get_session(self, session_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            return dict(row) if row else None

    def get_session_model_config_value(self, session_id, key):
        row = self.get_session(session_id) or {}
        return json.loads(row.get("model_config") or "{}").get(key)

    def session_ids_with_model_config_key(self, key):
        with sqlite3.connect(self.db_path) as conn:
            return [
                sid for sid, config in conn.execute("SELECT id, model_config FROM sessions")
                if json.loads(config or "{}").get(key) is not None
            ]

    def set_session_hidden(self, session_id, hidden):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE sessions SET hidden = ? WHERE id = ?", (hidden, session_id))

    def patch_session_model_config(self, session_id, patch):
        row = self.get_session(session_id) or {}
        config = json.loads(row.get("model_config") or "{}")
        config.update(patch)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE sessions SET model_config = ? WHERE id = ?", (json.dumps(config), session_id))

    def get_session_delete_targets(self, session_id):
        if not self.get_session(session_id):
            return []
        with sqlite3.connect(self.db_path) as conn:
            delegates = [
                cid
                for (cid,) in conn.execute(
                    "SELECT id FROM sessions WHERE parent_session_id = ? AND source = 'delegate'",
                    (session_id,),
                )
            ]
        return [session_id, *sorted(delegates)]

    def delete_session(self, session_id, *, expected_delete_ids, exclude_active_write_guards):
        targets = self.get_session_delete_targets(session_id)
        assert set(expected_delete_ids) == set(targets)
        assert exclude_active_write_guards
        with sqlite3.connect(self.db_path) as conn:
            for tid in targets:
                conn.execute("DELETE FROM messages WHERE session_id = ?", (tid,))
            cur = conn.executemany("DELETE FROM sessions WHERE id = ?", [(tid,) for tid in targets])
            return cur.rowcount > 0


@pytest.fixture(autouse=True)
def isolated_hermes_env(tmp_path, monkeypatch):
    """
    Fixtures setting an isolated HERMES_HOME, creating required subdirectories,
    and resetting IncognitoEngine before and after each test.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    # Even if hermes_state / hermes_cli happen to be importable, use isolated fallbacks.
    # Tests that need a database opt in with monkeypatch.setattr(engine, "SessionDB", MockSessionDB).
    import engine as _engine  # noqa: F401  (ensure the top-level module is loaded)
    for name in _ENGINE_MODULES:
        mod = sys.modules.get(name)
        if mod is None:
            continue
        monkeypatch.setattr(mod, "SessionDB", None, raising=False)
        monkeypatch.setattr(mod, "plugin_data_dir", None, raising=False)
        monkeypatch.setattr(mod, "load_config_readonly", lambda: {}, raising=False)

    sessions_dir = tmp_path / "sessions"
    hook_outputs_dir = tmp_path / "hook_outputs"
    plugin_data_dir = tmp_path / "plugin-data" / "incognito"

    sessions_dir.mkdir(parents=True, exist_ok=True)
    hook_outputs_dir.mkdir(parents=True, exist_ok=True)
    plugin_data_dir.mkdir(parents=True, exist_ok=True)

    # Initialize a mock state.db in isolated HERMES_HOME
    db_path = tmp_path / "state.db"
    mock_db = MockSessionDB(db_path)

    # Reset engine if engine module is importable
    try:
        import engine
        if hasattr(engine, "reset_engine"):
            engine.reset_engine()
        elif hasattr(engine, "IncognitoEngine") and hasattr(engine.IncognitoEngine, "reset"):
            engine.IncognitoEngine.reset()
    except ImportError:
        pass

    yield {
        "home": tmp_path,
        "sessions_dir": sessions_dir,
        "hook_outputs_dir": hook_outputs_dir,
        "plugin_data_dir": plugin_data_dir,
        "mock_db": mock_db,
    }

    # Post-test cleanup/reset
    try:
        import engine
        if hasattr(engine, "reset_engine"):
            engine.reset_engine()
        elif hasattr(engine, "IncognitoEngine") and hasattr(engine.IncognitoEngine, "reset"):
            engine.IncognitoEngine.reset()
    except ImportError:
        pass
