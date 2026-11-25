"""Incognito burn must purge a session's composer-cache attachment files.

The Desktop keeps two app-managed attachment caches outside the transcript:

- ``<userData>/composer-images/<name>``  — pasted/attached images (Electron main), and
- ``<HERMES_HOME>/composer-pastes/<name>.txt`` (plus legacy ``<userData>/composer-pastes``)
  — large plain-text pastes attached as chips.

``file.attach`` then stages a copy of the attached file under
``<HERMES_HOME>/attachments/`` and the saved message references THAT copy, orphaning
the composer original — burn must capture and purge both (same basename, same bytes).

Filenames carry no session id; the only mapping is the absolute path embedded in
``messages.content`` (``@image:`...``` / ``@file:`` attachments). Burn must capture those
paths before ``delete_session`` (same lease/retry pattern as the native-input media
purge), zero-fill + unlink the files, keep any still referenced by another session,
and let ``verify_zero_trace`` veto on survivors.
"""
import sqlite3

import engine as engine_mod
from engine import IncognitoEngine
from pathlib import Path


def _make_session(env, sess_id, content):
    (env["sessions_dir"] / f"{sess_id}.jsonl").write_text('{"role":"user","content":"x"}\n', encoding="utf-8")
    with sqlite3.connect(str(env["home"] / "state.db")) as conn:
        conn.execute("INSERT OR REPLACE INTO sessions (id, title) VALUES (?, ?)", (sess_id, "t"))
        conn.execute("INSERT OR REPLACE INTO messages (id, session_id, content) VALUES (?, ?, ?)",
                     (f"m-{sess_id}", sess_id, content))
        conn.commit()


def _roots(env):
    """Two fake composer roots: HERMES_HOME (env home) and a fake Electron userData."""
    user_data = env["home"] / "userdata" / "Hermes"
    return [env["home"], user_data]


def _engine(env, monkeypatch):
    eng = IncognitoEngine(home_dir=env["home"])
    monkeypatch.setattr(engine_mod, "SessionDB", type(env["mock_db"]))
    monkeypatch.setattr(eng, "_composer_cache_roots", lambda: _roots(env))
    eng.config["zero_fill_files"] = True
    return eng


def _make_composer_file(root, subdir, name, data=b"ZQK-COMPOSER-BYTES"):
    path = root / subdir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_extract_composer_refs():
    roots = [Path("/home/u/hermes"), Path("C:/Users/John Doe/AppData/Roaming/Hermes")]

    def _norm(paths):
        return {str(Path(p)) for p in paths}

    # Windows path, profile dir with a space, backtick-quoted @image: form
    win = "[Image attached at: C:\\Users\\John Doe\\AppData\\Roaming\\Hermes\\composer-images\\alex_603203.jpg]"
    assert _norm(engine_mod._composer_file_refs_in_text(win, roots)) == \
        _norm(["C:/Users/John Doe/AppData/Roaming/Hermes/composer-images/alex_603203.jpg"])
    # POSIX path with a spaced component
    posix = "@image:`/home/u/.config/Hermes/composer-images/a.png`"
    assert engine_mod._composer_file_refs_in_text(posix, roots) == set(), "userData on POSIX is not in roots"
    # HERMES_HOME paste (root given)
    paste = "@file:`/home/u/hermes/composer-pastes/pasted_content_20261123_120000_ab12cd.txt`"
    assert _norm(engine_mod._composer_file_refs_in_text(paste, roots)) == \
        _norm(["/home/u/hermes/composer-pastes/pasted_content_20261123_120000_ab12cd.txt"])
    # file:// URI with percent-encoded spaces
    uri = "file:///C:/Users/John%20Doe/AppData/Roaming/Hermes/composer-images/c%20d.png"
    assert _norm(engine_mod._composer_file_refs_in_text(uri, roots)) == \
        _norm(["C:/Users/John Doe/AppData/Roaming/Hermes/composer-images/c d.png"])
    # several refs in one message
    multi = (
        f"{win} plus /home/u/hermes/composer-pastes/pasted_content_1_aaa.txt"
        " and /home/u/hermes/composer-pastes/pasted_content_2_bbb.txt"
    )
    assert len(engine_mod._composer_file_refs_in_text(multi, roots)) == 3
    # negatives: unknown root, wrong dir name, traversal, no cache dir at all
    assert engine_mod._composer_file_refs_in_text("/tmp/Hermes/composer-images/x.png", roots) == set()
    assert engine_mod._composer_file_refs_in_text("/home/u/hermes/composer-imagez/x.png", roots) == set()
    assert engine_mod._composer_file_refs_in_text("/home/u/hermes/composer-images/../x.png", roots) == set()
    assert engine_mod._composer_file_refs_in_text("just some text", roots) == set()
    # an attachments-dir ref outside a known root is not ours to touch
    assert engine_mod._composer_file_refs_in_text(
        "/tmp/Hermes/attachments/pasted_content_1_aaa.txt", roots
    ) == set()


def test_extract_staging_attachments_ref():
    """file.attach stages a copy in <HERMES_HOME>/attachments and the saved message
    references THAT path, not the composer-pastes original (live format, 2026-11-24)."""
    roots = [Path("C:/Users/jd/AppData/Local/hermes")]
    content = (
        "@file:C:\\Users\\jd\\AppData\\Local\\hermes\\attachments"
        "\\pasted_content_2026-11-24_04-16-21-556_2d5e21.txt\n\n"
        "--- Attached Context ---\n\n\ud83d\udcc4 @file:C:/Users/jd/AppData/Local/hermes/"
        "attachments/pasted_content_2026-11-24_04-16-21-556_2d5e21.txt"
    )
    assert engine_mod._composer_file_refs_in_text(content, roots) == {
        str(Path("C:/Users/jd/AppData/Local/hermes/attachments/pasted_content_2026-11-24_04-16-21-556_2d5e21.txt"))
    }
    # the word 'attachments' in prose alone must not match
    assert engine_mod._composer_file_refs_in_text(
        "see the attachments folder", roots
    ) == set()


def test_burn_purges_unique_composer_files(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    home_root, user_root = _roots(env)

    img = _make_composer_file(user_root, "composer-images", "alex_603203.jpg")
    paste = _make_composer_file(home_root, "composer-pastes", "pasted_content_1_aaa.txt", b"personal paste")
    sess_id = "sess-composer-burn"
    _make_session(
        env, sess_id,
        f"[Image attached at: {img.as_posix()}] and @file:`{paste.as_posix()}`",
    )

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True, res
    assert res.get("composer_files_purged") == 2, res
    assert res.get("pending_burn") is False, res
    assert res.get("db_deleted") is True, res
    assert not img.exists()
    assert not paste.exists()

    vt = eng.verify_zero_trace(sess_id)
    assert vt.get("composer_files_found") == 0
    assert vt.get("zero_trace") is True, vt


def test_burn_keeps_shared_composer_file(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    home_root, _ = _roots(env)

    shared = _make_composer_file(home_root, "composer-pastes", "shared_note.txt")
    content = f"@file:`{shared.as_posix()}`"
    _make_session(env, "sess-a", content)
    _make_session(env, "sess-b", content)  # another session still owns these bytes

    eng.enable_session("sess-a", mode="strict")
    res = eng.burn_session("sess-a", reason="burn")
    assert res.get("ok") is True, res
    assert res.get("composer_files_purged") == 0, res  # kept, not purged
    assert shared.exists()


def test_verify_zero_trace_flags_surviving_composer_file(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    home_root, _ = _roots(env)

    paste = _make_composer_file(home_root, "composer-pastes", "leak_paste.txt")
    sess_id = "sess-composer-verify"
    _make_session(env, sess_id, f"@file:`{paste.as_posix()}`")

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True and res.get("composer_files_purged") == 1, res
    assert not paste.exists()

    # Simulate a residual (e.g. a re-write race after the unlink).
    paste.write_bytes(b"residual-bytes")
    vt = eng.verify_zero_trace(sess_id)
    assert vt.get("composer_files_found") == 1, vt
    assert vt.get("zero_trace") is False, vt


def test_burn_deferred_retry_purges_composer_files(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    monkeypatch.setattr(eng, "_schedule_deferred_burn", lambda *a, **k: None)  # explicit retry below
    home_root, _ = _roots(env)
    block = home_root / "composer-pastes" / "locked_note.txt"
    block.parent.mkdir(parents=True, exist_ok=True)
    block.mkdir()
    sess_id = "sess-composer-retry"
    _make_session(env, sess_id, f"@file:`{block.as_posix()}`")

    eng.enable_session(sess_id, mode="strict")
    first = eng.burn_session(sess_id, reason="burn")
    assert first.get("ok") is True, first
    assert first.get("pending_burn") is True, first   # dir can't be unlinked: deferred
    assert first.get("composer_files_purged") == 0, first

    # The lock clears between attempts; the retry reads the ref from the burn lease
    # (the message rows are already gone).
    block.rmdir()
    block.write_bytes(b"ZQK-COMPOSER-BYTES")
    second = eng.burn_session(sess_id, reason="burn")
    assert second.get("ok") is True, second
    assert second.get("composer_files_purged") == 1, second
    assert second.get("pending_burn") is False, second
    assert not block.exists()

    vt = eng.verify_zero_trace(sess_id)
    assert vt.get("composer_files_found") == 0
    assert vt.get("zero_trace") is True, vt


def test_burn_without_composer_refs_is_unchanged(isolated_hermes_env, monkeypatch):
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)

    sha = "0" * 64
    name = "dashboard_20261122_000000_abcdef_image_123456.png"
    native = env["home"] / "cache" / "documents" / "native-inputs" / sha / name
    native.parent.mkdir(parents=True, exist_ok=True)
    native.write_bytes(b"ZQK-MEDIA-BYTES")
    sess_id = "sess-native-only"
    _make_session(env, sess_id, f"[Image attached at: {native.as_posix()}]")

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True, res
    assert res.get("media_files_purged") == 1, res
    assert res.get("composer_files_purged") == 0, res
    assert res.get("composer_purged") == [], res
    assert not native.exists()


def test_burn_purges_staged_copy_and_composer_twin(isolated_hermes_env, monkeypatch):
    """The live 2026-11-24 leak: the message references <HERMES_HOME>/attachments/<name>,
    while the composer-pastes original (same bytes, never referenced again) survives."""
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    home_root, _ = _roots(env)

    name = "pasted_content_2026-11-24_04-16-21-556_2d5e21.txt"
    staged = _make_composer_file(home_root, "attachments", name, b"personal paste bytes")
    twin = _make_composer_file(home_root, "composer-pastes", name, b"personal paste bytes")
    sess_id = "sess-paste-staging"
    _make_session(env, sess_id, f"@file:{staged.as_posix()}\n\n--- Attached Context ---")

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True, res
    assert res.get("composer_files_purged") == 2, res  # staged copy AND its twin
    assert res.get("pending_burn") is False, res
    assert not staged.exists()
    assert not twin.exists()

    vt = eng.verify_zero_trace(sess_id)
    assert vt.get("composer_files_found") == 0, vt
    assert vt.get("zero_trace") is True, vt


def test_burn_keeps_shared_staged_file_and_twin(isolated_hermes_env, monkeypatch):
    """Another live session referencing the same staged path keeps both the copy and its
    composer twin (staging names are unique per paste, so a basename match is the same file)."""
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    home_root, _ = _roots(env)

    name = "pasted_content_2026-11-24_05-00-00-000_aaaa11.txt"
    staged = _make_composer_file(home_root, "attachments", name, b"shared bytes")
    twin = _make_composer_file(home_root, "composer-pastes", name, b"shared bytes")
    content = f"@file:{staged.as_posix()}"
    _make_session(env, "sess-shared-a", content)
    _make_session(env, "sess-shared-b", content)  # another session still owns these bytes

    eng.enable_session("sess-shared-a", mode="strict")
    res = eng.burn_session("sess-shared-a", reason="burn")
    assert res.get("ok") is True, res
    assert res.get("composer_files_purged") == 0, res
    assert staged.exists()
    assert twin.exists()


def test_burn_ignores_unreferenced_attachments_file(isolated_hermes_env, monkeypatch):
    """A file sitting in attachments/ that the burning session never referenced is out
    of scope for this burn (no scope creep into other sessions' staged files)."""
    env = isolated_hermes_env
    eng = _engine(env, monkeypatch)
    home_root, _ = _roots(env)

    stranger = _make_composer_file(home_root, "attachments", "other_session_file.txt")
    paste = _make_composer_file(home_root, "composer-pastes", "mine_2026-11-24_06-00-00_112233.txt")
    sess_id = "sess-scope-check"
    _make_session(env, sess_id, f"@file:`{paste.as_posix()}`")

    eng.enable_session(sess_id, mode="strict")
    res = eng.burn_session(sess_id, reason="burn")
    assert res.get("ok") is True, res
    assert res.get("composer_files_purged") == 1, res
    assert not paste.exists()
    assert stranger.exists()
