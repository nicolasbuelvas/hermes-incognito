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
                    metadata TEXT
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

    def get_session(self, session_id: str):
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, created_at, updated_at, metadata FROM sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                return {"id": row[0], "title": row[1], "created_at": row[2], "updated_at": row[3], "metadata": row[4]}
            return None

    def delete_session(self, session_id: str):
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            cursor.execute("DELETE FROM messages WHERE id = ?", (session_id,))
            conn.commit()


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
