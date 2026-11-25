"""Gate 2: burning an incognito session must purge RetainDB memories recorded against it.

The archive store (RetainDB) is the one surface the local zero-trace burn does not reach by
itself; auto-ingestion can outlive the session. ``purge_memory_store`` is best-effort with
log-only failures so archive availability can never block a local burn, and register() wires
it into the existing ``on_burn_complete`` callback so every burned target id (including
cascaded ancestors) is covered.
"""
import json
import sys
import urllib.error

import pytest  # noqa: F401  (parity with sibling test modules)

import engine as engine_mod
from engine import IncognitoEngine

_SID = "sid-archive-777"


def _fake_secrets(monkeypatch, api_key="test-key", base_url="http://localhost:3111", project="default"):
    values = {"RETAINDB_API_KEY": api_key, "RETAINDB_BASE_URL": base_url, "RETAINDB_PROJECT": project}
    monkeypatch.setattr(engine_mod, "get_secret", lambda name, default="": values.get(name, default))


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stub_urlopen(monkeypatch, handler):
    calls = []

    def fake(req, timeout=None):
        calls.append((req.get_method(), req.full_url))
        return handler(req)

    monkeypatch.setattr(engine_mod.urllib.request, "urlopen", fake)
    return calls


def _listing_body(ids):
    return json.dumps({"memories": [{"id": i} for i in ids]}).encode()


def test_purge_deletes_session_memories(isolated_hermes_env, monkeypatch):
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    _fake_secrets(monkeypatch)
    calls = _stub_urlopen(monkeypatch, lambda req: _FakeResp(
        b"{}" if req.get_method() == "DELETE" else _listing_body(["m1", "m2", "m3"])))
    result = eng.purge_memory_store(_SID)
    assert result.get("purged") == 3
    methods = [m for m, _ in calls]
    assert methods[0] == "GET" and methods[1:] == ["DELETE"] * 3
    get_url = calls[0][1]
    # SOTA session-scoped list (the legacy /v1/memories?session_id= filter is not honored
    # on the deployed server); no legacy list URL.
    assert f"/v1/memory/session/{_SID}" in get_url
    assert "project=default" in get_url and "session_id=" not in get_url
    for mid in ("m1", "m2", "m3"):
        delete_urls = [url for m, url in calls[1:]]
        assert any(f"/v1/memory/{mid}" in url for url in delete_urls)
        assert not any(f"/v1/memories/{mid}" in url for url in delete_urls)


def test_purge_404_is_idempotent_and_does_not_abort(isolated_hermes_env, monkeypatch):
    """A 404 on one memory (already gone) must not abort the rest of the purge."""
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    _fake_secrets(monkeypatch)
    calls = []

    def handler(req):
        if req.get_method() == "DELETE":
            if "/v1/memory/m1" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "gone", {}, None)
            return _FakeResp(b"{}")
        return _FakeResp(_listing_body(["m1", "m2", "m3"]))

    calls = _stub_urlopen(monkeypatch, handler)
    result = eng.purge_memory_store(_SID)
    assert result.get("purged") == 3  # m1 (404) + m2 + m3
    assert "error" not in result
    assert [m for m, _ in calls] == ["GET", "DELETE", "DELETE", "DELETE"]


def test_purge_skips_pending_overlay_ids(isolated_hermes_env, monkeypatch):
    """Overlay entries (id 'pending:job:idx') are listed but not deletable by id."""
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    _fake_secrets(monkeypatch)
    body = json.dumps({"memories": [{"id": "pending:job1:0"}, {"id": "m1"}]}).encode()
    calls = _stub_urlopen(monkeypatch, lambda req: _FakeResp(
        b"{}" if req.get_method() == "DELETE" else body))
    result = eng.purge_memory_store(_SID)
    assert result.get("purged") == 1
    assert [m for m, _ in calls] == ["GET", "DELETE"]


def test_purge_empty_session(isolated_hermes_env, monkeypatch):
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    _fake_secrets(monkeypatch)
    calls = _stub_urlopen(monkeypatch, lambda req: _FakeResp(b"{}" if req.get_method() == "DELETE"
                                                             else _listing_body([])))
    result = eng.purge_memory_store(_SID)
    assert result.get("purged") == 0
    assert [m for m, _ in calls] == ["GET"]


def test_purge_skipped_when_not_configured(isolated_hermes_env, monkeypatch):
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    monkeypatch.setattr(engine_mod, "get_secret", lambda name, default="": "")
    called = []
    monkeypatch.setattr(engine_mod.urllib.request, "urlopen", lambda *a, **k: called.append(1))
    result = eng.purge_memory_store(_SID)
    assert result.get("skipped")
    assert called == []


def test_purge_survives_server_failure(isolated_hermes_env, monkeypatch):
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    _fake_secrets(monkeypatch)

    def boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(engine_mod.urllib.request, "urlopen", boom)
    result = eng.purge_memory_store(_SID)
    assert "error" in result and result.get("purged", 0) == 0


def test_register_wires_purge_into_burn_complete(isolated_hermes_env, monkeypatch):
    """register() composes purge + Desktop notify into on_burn_complete; burn covers the sid.

    Load the plugin through hermes_sim.load_plugin() so class and module identity match the
    live host: the tests' top-level ``engine`` import is a second module object, and calling
    its get_engine() first in-process would flip the canonical-module delegation and break
    the sim-based tests that run afterwards.
    """
    from unittest.mock import MagicMock

    import hermes_sim

    home = isolated_hermes_env["home"]
    purged, notified = [], []
    plugin = hermes_sim.load_plugin()
    pkg_engine = sys.modules["hermes_plugin_incognito_test.engine"]
    values = {"RETAINDB_API_KEY": "test-key", "RETAINDB_BASE_URL": "http://localhost:3111",
              "RETAINDB_PROJECT": "default"}
    monkeypatch.setattr(pkg_engine, "get_secret", lambda name, default="": values.get(name, default))
    monkeypatch.setattr(pkg_engine.IncognitoEngine, "purge_memory_store",
                        lambda self, sid: (purged.append(sid), {"purged": 0})[1])

    ctx = MagicMock()
    ctx.emit_to_session = lambda sid, event, payload: notified.append(sid)
    plugin.register(ctx)

    eng = pkg_engine.get_engine(home_dir=home)
    monkeypatch.setattr(pkg_engine, "SessionDB", type(isolated_hermes_env["mock_db"]))  # DB-backed burn (completes)
    eng.enable_session(_SID, mode="standard")
    assert eng.is_incognito(_SID) is True
    result = eng.burn_session(_SID, reason="test")
    assert result["ok"] is True
    assert result["pending_burn"] is False
    assert _SID in purged
    assert _SID in notified


def test_endpoints_local_no_key_resolves(isolated_hermes_env, monkeypatch):
    """A localhost store served without auth must resolve even with no RETAINDB_API_KEY."""
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    values = {"RETAINDB_API_KEY": "", "RETAINDB_BASE_URL": "http://localhost:3111", "RETAINDB_PROJECT": "default"}
    monkeypatch.setattr(engine_mod, "get_secret", lambda name, default="": values.get(name, default))
    ep = eng._retaindb_endpoints()
    assert ep is not None
    assert ep == ("http://localhost:3111", "default", "")


def test_endpoints_remote_no_key_skips(isolated_hermes_env, monkeypatch):
    """A remote store still requires a key; no key → unconfigured (no behavior change for cloud)."""
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    values = {"RETAINDB_API_KEY": "", "RETAINDB_BASE_URL": "https://api.retaindb.com", "RETAINDB_PROJECT": "proj"}
    monkeypatch.setattr(engine_mod, "get_secret", lambda name, default="": values.get(name, default))
    assert eng._retaindb_endpoints() is None


def test_endpoints_local_from_config_no_secret_key(isolated_hermes_env, monkeypatch):
    """No secrets at all, but config provides a loopback base_url → resolves. This is the real local-store path."""
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    monkeypatch.setattr(engine_mod, "get_secret", lambda name, default="": "")
    monkeypatch.setattr(engine_mod, "load_config_readonly",
                        lambda: {"memory": {"retaindb": {"base_url": "http://127.0.0.1:3111", "project": "default"}}})
    ep = eng._retaindb_endpoints()
    assert ep is not None
    assert ep == ("http://127.0.0.1:3111", "default", "")


def test_is_local_retaindb_url():
    assert engine_mod._is_local_retaindb_url("http://localhost:3111") is True
    assert engine_mod._is_local_retaindb_url("http://127.0.0.1:3111/") is True
    assert engine_mod._is_local_retaindb_url("http://[::1]:3111") is True
    assert engine_mod._is_local_retaindb_url("https://api.retaindb.com") is False
    assert engine_mod._is_local_retaindb_url("") is False


def test_verify_zero_trace_reports_retaindb(isolated_hermes_env, monkeypatch):
    """verify_zero_trace probes the archive store and folds surviving memories into the verdict."""
    eng = IncognitoEngine(home_dir=isolated_hermes_env["home"])
    monkeypatch.setattr(engine_mod, "get_secret", lambda name, default="": "")
    monkeypatch.setattr(engine_mod, "load_config_readonly",
                        lambda: {"memory": {"retaindb": {"base_url": "http://localhost:3111", "project": "default"}}})
    sid = "sid-verify-ret-1"

    monkeypatch.setattr(engine_mod.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResp(_listing_body(["m1", "m2"])))
    res = eng.verify_zero_trace(sid)
    assert res["retaindb_status"] == "ok"
    assert res["retaindb_memories_found"] == 2
    assert res["zero_trace"] is False  # surviving memories veto the verdict

    monkeypatch.setattr(engine_mod.urllib.request, "urlopen",
                        lambda *a, **k: _FakeResp(_listing_body([])))
    res2 = eng.verify_zero_trace(sid)
    assert res2["retaindb_memories_found"] == 0
    assert res2["zero_trace"] is True  # a clean store does not veto
