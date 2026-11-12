import json
import os
import sys
import tempfile
import sqlite3
import pytest
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
HERMES_APP_DATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".hermes"))) / "hermes" / "hermes-agent"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if HERMES_APP_DATA.exists() and str(HERMES_APP_DATA) not in sys.path:
    sys.path.insert(0, str(HERMES_APP_DATA))


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
                    metadata TEXT,
                    model_config TEXT
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

    def create_session(self, session_id: str, source: str = "cli", model: str = "gpt-4", **kwargs) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions (id, title) VALUES (?, ?)",
                (session_id, kwargs.get("title", "")),
            )
            conn.commit()

    def get_session(self, session_id: str):
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, title, created_at, updated_at, metadata, model_config FROM sessions WHERE id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "title": row[1],
                    "created_at": row[2],
                    "updated_at": row[3],
                    "metadata": row[4],
                    "model_config": row[5],
                }
            return None

    def delete_session(self, session_id: str, sessions_dir=None, include_compression_chain: bool = False, **kwargs):
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cur_m = cursor.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            cur_s = cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            return (cur_s.rowcount > 0) or (cur_m.rowcount > 0)

    def set_session_hidden(self, session_id: str, hidden: bool) -> None:
        pass

    def patch_session_model_config(self, session_id: str, patch: dict) -> None:
        if not session_id or not patch:
            return
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute("SELECT model_config FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if not row:
                return
            current = json.loads(row[0]) if row[0] else {}
            for k, v in patch.items():
                if v is None:
                    current.pop(k, None)
                else:
                    current[k] = v
            conn.execute(
                "UPDATE sessions SET model_config = ? WHERE id = ?",
                (json.dumps(current) if current else None, session_id),
            )
            conn.commit()

    def get_session_model_config_value(self, session_id: str, key: str, default=None):
        sess = self.get_session(session_id) or {}
        raw = sess.get("model_config")
        if not raw:
            return default
        data = json.loads(raw)
        return data.get(key, default) if isinstance(data, dict) else default

    def session_ids_with_model_config_key(self, key: str) -> list[str]:
        out: list[str] = []
        with sqlite3.connect(str(self.db_path)) as conn:
            for sid, raw in conn.execute("SELECT id, model_config FROM sessions WHERE model_config IS NOT NULL"):
                try:
                    mc = json.loads(raw)
                    if isinstance(mc, dict) and key in mc and mc[key] is not None:
                        out.append(sid)
                except Exception:
                    pass
        return out

    def get_session_delete_targets(self, session_id: str) -> list[str]:
        return [session_id]

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def isolated_hermes_env(tmp_path, monkeypatch):
    """
    Fixtures setting an isolated HERMES_HOME, creating required subdirectories,
    and resetting IncognitoEngine before and after each test.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    sessions_dir = tmp_path / "sessions"
    hook_outputs_dir = tmp_path / "hook_outputs"
    plugin_data_dir = tmp_path / "plugin-data" / "incognito"

    sessions_dir.mkdir(parents=True, exist_ok=True)
    hook_outputs_dir.mkdir(parents=True, exist_ok=True)
    plugin_data_dir.mkdir(parents=True, exist_ok=True)

    # Initialize state.db with real SessionDB schema if available, else MockSessionDB
    db_path = tmp_path / "state.db"
    mock_db = None
    try:
        from hermes_state import SessionDB
        real_db = SessionDB(db_path=db_path)
        if hasattr(real_db, "close"):
            real_db.close()
        mock_db = real_db
    except Exception:
        mock_db = MockSessionDB(db_path)

    # Reset engine if engine module is importable, and supply MockSessionDB fallback when hermes_state isn't available
    try:
        import engine
        if getattr(engine, "SessionDB", None) is None:
            monkeypatch.setattr(engine, "SessionDB", MockSessionDB)
        if hasattr(engine, "reset_engine"):
            engine.reset_engine()
        elif hasattr(engine, "IncognitoEngine") and hasattr(engine.IncognitoEngine, "reset"):
            engine.IncognitoEngine.reset()
    except ImportError:
        pass
    pkg_engine = sys.modules.get("hermes_plugin_incognito_test.engine")
    if pkg_engine is not None:
        if getattr(pkg_engine, "SessionDB", None) is None:
            monkeypatch.setattr(pkg_engine, "SessionDB", MockSessionDB)
        if hasattr(pkg_engine, "reset_engine"):
            pkg_engine.reset_engine()

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
