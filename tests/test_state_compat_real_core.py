"""E2E tests against the real Hermes core.

The rest of this suite is core-free by design (see conftest.py): tests must
not pick up a real SessionDB, config, or plugin storage from the host
install. This module exercises the engine against the actual storage
interface and skips unless HERMES_CORE_PATH points at a hermes-agent
checkout that ships hermes_state.

Reproduces the regression shipped in the Hermes 2026-11-23 update
(``refactor(state)!: remove the old session store``): ``hermes_state`` is now
a compatibility shim that carries only the verbs the plugin guide lists and
raises AttributeError for everything else. The engine still calls five of
the dropped verbs, and each of them broke:

- ``masking_active()`` -> ``pre_llm_call`` vetoes every non-incognito send
  ("Incognito could not mask this turn (AttributeError); blocking it.")
- ``enable_session()`` / ``disable_session()`` -> slash arm/disarm reports
  "Could not activate / update chat history. Try again."
- burn/sweep -> ``session_ids_with_model_config_key`` and
  ``get_session_delete_targets`` are swallowed by broad excepts, silently
  losing DB-marker protection.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORE_PATH = os.environ.get("HERMES_CORE_PATH", "")

requires_core = pytest.mark.skipif(
    not CORE_PATH or not (Path(CORE_PATH) / "hermes_state.py").is_file(),
    reason="HERMES_CORE_PATH does not point at a hermes-agent checkout",
)


@pytest.fixture(autouse=True)
def isolated_hermes_env(tmp_path, monkeypatch):
    """Override the conftest autouse fixture for this module.

    The core-free suite gets a mock legacy-schema state.db planted in the
    isolated home; these tests open the store through the real core, whose
    schema init must create state.db from scratch. Same home isolation, no
    mock file.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    sessions_dir = tmp_path / "sessions"
    hook_outputs_dir = tmp_path / "hook_outputs"
    plugin_data_dir = tmp_path / "plugin-data" / "incognito"
    for d in (sessions_dir, hook_outputs_dir, plugin_data_dir):
        d.mkdir(parents=True, exist_ok=True)
    yield {
        "home": tmp_path,
        "sessions_dir": sessions_dir,
        "hook_outputs_dir": hook_outputs_dir,
        "plugin_data_dir": plugin_data_dir,
        "mock_db": None,
    }

_CORE_PREFIXES = ("hermes_state", "persistence", "persistence_assembly", "session_retention")


def _is_core_module(name: str) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in _CORE_PREFIXES)


@pytest.fixture()
def real_engine(tmp_path, monkeypatch):
    """A fresh engine module imported with the real core on sys.path.

    A fresh module is required because the engine binds hermes_state's
    SessionDB at import time; the rest of the suite imports the engine
    core-free and would otherwise keep the stale binding.

    The sibling suite also leaks the plugin's flat tools.py into
    sys.modules["tools"] (plugin __init__ fallback during collection);
    save and evict it so the core's deferred ``from tools...`` imports
    resolve to the core package, then restore it afterwards.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.syspath_prepend(CORE_PATH)
    evicted = {}
    for name in list(sys.modules):
        if _is_core_module(name) or name == "tools":
            evicted[name] = sys.modules.pop(name)
    spec = importlib.util.spec_from_file_location(
        "incognito_engine_real_core", PROJECT_ROOT / "engine.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    yield mod
    for name in list(sys.modules):
        if _is_core_module(name) or name == spec.name:
            del sys.modules[name]
    sys.modules.update(evicted)


def _make_session(home: Path, session_id: str, source: str = "cli") -> str:
    from persistence_assembly import open_persistence, profile_scope
    from persistence.conversation.sessions import NewSession

    with open_persistence(profile_scope(home=home), eager=True) as store:
        return str(store.sessions.create(NewSession(session_id=session_id, source=source)))


def _store(home: Path):
    from persistence_assembly import open_persistence, profile_scope

    return open_persistence(profile_scope(home=home), eager=True)


@requires_core
def test_masking_active_ordinary_chat_is_false(real_engine, tmp_path):
    """The send block: a plain chat's masking check must not raise.

    Pre-fix this raised AttributeError, which pre_llm_call converts into the
    veto "Incognito didn't send this message because it couldn't mask your
    personal details."
    """
    _make_session(tmp_path, "local-plain-sid")
    eng = real_engine.IncognitoEngine(home_dir=tmp_path)
    assert eng.masking_active("local-plain-sid") is False


@requires_core
def test_masking_active_reads_redact_marker(real_engine, tmp_path):
    """The stored incognito marker decides whether masking is enabled."""
    sid = _make_session(tmp_path, "local-marked-sid")
    eng = real_engine.IncognitoEngine(home_dir=tmp_path)
    db_path = tmp_path / "state.db"
    with real_engine._open_session_db(db_path) as db:
        db.patch_session_model_config(sid, {"incognito": {"mode": "standard", "redact_pii": True}})
    assert eng.masking_active(sid) is True
    with real_engine._open_session_db(db_path) as db:
        db.patch_session_model_config(sid, {"incognito": {"mode": "standard", "redact_pii": False}})
    assert eng.masking_active(sid) is False


@requires_core
def test_enable_disable_round_trip(real_engine, tmp_path):
    """Slash arm/disarm: history marker and visibility round-trip.

    Pre-fix both directions failed with "Could not activate / update chat
    history. Try again." because _set_history_state hit the dropped verbs.
    """
    sid = _make_session(tmp_path, "local-arm-sid")
    eng = real_engine.IncognitoEngine(home_dir=tmp_path)

    on = eng.enable_session(sid, mode="standard")
    assert on.get("ok") is True, on
    with _store(tmp_path) as store:
        marker = store.sessions.get_model_config_value(sid, "incognito")
        row = store.sessions.get(sid)
    assert isinstance(marker, dict) and marker.get("mode") == "standard", marker
    assert row is not None and row.hidden is True

    off = eng.disable_session(sid)
    assert off.get("ok") is True, off
    with _store(tmp_path) as store:
        assert store.sessions.get_model_config_value(sid, "incognito") is None
        row = store.sessions.get(sid)
    assert row is not None and row.hidden is False


@requires_core
def test_burn_verbs_and_delete_cascade(real_engine, tmp_path):
    """Burn path: marker discovery, delete-target planning, fenced delete."""
    parent = _make_session(tmp_path, "local-burn-sid")
    _make_session(tmp_path, "local-burn-child-sid")
    eng = real_engine.IncognitoEngine(home_dir=tmp_path)
    db_path = tmp_path / "state.db"

    db = real_engine._open_session_db(db_path)
    try:
        db.patch_session_model_config(parent, {"incognito": {"mode": "strict", "redact_pii": True}})
        found = db.session_ids_with_model_config_key("incognito")
        assert parent in list(found)
        targets = list(db.get_session_delete_targets(parent))
        assert parent in targets
        assert db.delete_session(
            parent, expected_delete_ids=targets, exclude_active_write_guards=True
        ) is True
    finally:
        db.close()

    with _store(tmp_path) as store:
        assert store.sessions.get(parent) is None
        assert store.sessions.get_model_config_value(parent, "incognito") is None
