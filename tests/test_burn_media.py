"""Incognito burn must purge a session's native-input media bytes.

Before this fix the burn zero-filled the transcript + hook outputs but left the committed
image bytes under ``<home>/cache/documents/native-inputs/<sha256>/<name>``. The reference lives
in ``messages.content`` (``[Image attached at: ...native-inputs/<sha256>/<name>]``), is captured
before ``delete_session`` and persisted in the burn lease, and the store path is scrubbed +
reported in the zero-trace receipt. A media ref still owned by another session is kept.
"""
import sqlite3

import engine as engine_mod
from engine import IncognitoEngine


def _native_root(env):
    return env["home"] / "cache" / "documents" / "native-inputs"


def _make_media(env, sha, name, data=b"ZQK-MEDIA-BYTES"):
    path = _native_root(env) / sha / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _make_session(env, sess_id, content):
    (env["sessions_dir"] / f"{sess_id}.jsonl").write_text('{"role":"user","content":"x"}\n', encoding="utf-8")
    with sqlite3.connect(str(env["home"] / "state.db")) as conn:
        conn.execute("INSERT OR REPLACE INTO sessions (id, title) VALUES (?, ?)", (sess_id, "t"))
        conn.execute("INSERT OR REPLACE INTO messages (id, session_id, content) VALUES (?, ?, ?)",
                     (f"m-{sess_id}", sess_id, content))
        conn.commit()


def test_extract_media_refs():
    sha1 = "0" * 64
    sha2 = "f" * 64
    win = f"[Image attached at: C:\\Users\\x\\cache\\documents\\native-inputs\\{sha1}\\a.png]"
    assert engine_mod._extract_media_refs(win) == {(sha1, "a.png")}
    fwd = f"[Image attached at: /home/x/cache/documents/native-inputs/{sha2}/b.jpg]"
    assert engine_mod._extract_media_refs(fwd) == {(sha2, "b.jpg")}
    assert engine_mod._extract_media_refs("just some text") == set()
    multi = f"native-inputs\\{sha1}\\a.png ... native-inputs/{sha2}/b.jpg"
    assert engine_mod._extract_media_refs(multi) == {(sha1, "a.png"), (sha2, "b.jpg")}
    # a content hash the wrong length is not a native-input ref
    assert engine_mod._extract_media_refs(f"native-inputs/{'a' * 60}/x.png") == set()


def test_burn_purges_unique_media(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = IncognitoEngine(home_dir=env["home"])
    monkeypatch.setattr(engine_mod, "SessionDB", type(env["mock_db"]))
    eng.config["zero_fill_files"] = True

    sha = "0" * 64
    name = "dashboard_20261122_000000_abcdef_image_123456.png"
    media_file = _make_media(env, sha, name)
    sess_id = "sess-media-burn"
    _make_session(env, sess_id, f"[Image attached at: {_native_root(env).as_posix()}/{sha}/{name}]")

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True, res
    assert res.get("media_files_purged") == 1, res
    assert res.get("pending_burn") is False, res
    assert res.get("db_deleted") is True, res
    # bytes gone and the empty content-hash dir removed
    assert not media_file.exists()
    assert not (_native_root(env) / sha).exists()

    vt = eng.verify_zero_trace(sess_id)
    assert vt.get("media_files_found") == 0
    assert vt.get("zero_trace") is True, vt


def test_burn_keeps_shared_media(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = IncognitoEngine(home_dir=env["home"])
    monkeypatch.setattr(engine_mod, "SessionDB", type(env["mock_db"]))

    sha = "a" * 64
    name = "shared_image.png"
    media_file = _make_media(env, sha, name)
    content = f"[Image attached at: {_native_root(env).as_posix()}/{sha}/{name}]"
    _make_session(env, "sess-a", content)
    _make_session(env, "sess-b", content)  # another session still owns these bytes

    # Only burn sess-a; the shared image must survive for sess-b.
    eng.enable_session("sess-a", mode="strict")
    res = eng.burn_session("sess-a", reason="burn")
    assert res.get("ok") is True, res
    assert res.get("media_files_purged") == 0, res  # kept, not purged
    assert media_file.exists()
    assert (_native_root(env) / sha).exists()


def test_verify_zero_trace_flags_surviving_media(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = IncognitoEngine(home_dir=env["home"])
    monkeypatch.setattr(engine_mod, "SessionDB", type(env["mock_db"]))

    sha = "b" * 64
    name = "leak_image.png"
    media_file = _make_media(env, sha, name)
    sess_id = "sess-media-verify"
    _make_session(env, sess_id, f"[Image attached at: {_native_root(env).as_posix()}/{sha}/{name}]")

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True and res.get("media_files_purged") == 1, res
    assert not media_file.exists()

    # Simulate a residual (e.g. a re-write race after the unlink): the receipt lists the ref as
    # purged but the bytes are back on disk. verify_zero_trace must veto the verdict. The scrub
    # also removed the empty content-hash dir, so a re-write recreates it first.
    media_file.parent.mkdir(parents=True, exist_ok=True)
    media_file.write_bytes(b"residual-bytes")
    vt = eng.verify_zero_trace(sess_id)
    assert vt.get("media_files_found") == 1, vt
    assert vt.get("zero_trace") is False, vt
