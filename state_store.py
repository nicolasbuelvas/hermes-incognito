"""Incognito's view of the profile's ``state.db`` over the Hermes 0.23 storage interface.

Hermes 0.23 rebuilt ``hermes_state.SessionDB`` as a migration-only facade: any method outside
its plugin-guide whitelist raises ``AttributeError`` on lookup, and every verb this plugin
needed except ``get_session``/``delete_session`` was cut. The v0.23.3 incident (issue #7):
the facade's ``AttributeError`` fired inside the fail-closed ``pre_llm_call`` handler and
blocked every turn. The facade itself is removed in v0.27.0.

``StateStore`` keeps the narrow surface ``engine`` uses, implemented solely on
``persistence_assembly`` store handles. Readers open per call against the exact database
file; writers share the process's writer for the owning profile's store.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Optional

try:
    from persistence_assembly import open_persistence, open_persistence_reader, profile_scope
except ImportError:  # standalone/pytest: engine treats an unavailable store as "no DB"
    open_persistence = None  # type: ignore[assignment]
    open_persistence_reader = None  # type: ignore[assignment]
    profile_scope = None  # type: ignore[assignment]

try:
    from gateway.session_ingress_media import native_inputs_root
except ImportError:
    native_inputs_root = None  # type: ignore[assignment]


def _media_root(db_path: Path) -> str:
    """The profile's retained media root for delete retirement, as the store verbs require it."""
    if native_inputs_root is not None:
        try:
            return str(native_inputs_root())
        except Exception:
            pass
    return str(db_path.parent / "media")


class StateStore:
    """Session rows, Incognito markers, and lineage deletes via the storage interface."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)

    # -- handle plumbing ---------------------------------------------------------------

    def _reader(self):
        return open_persistence_reader(self.db_path)

    def _writer(self):
        return open_persistence(profile_scope(home=self.db_path.parent))

    def close(self) -> None:
        return None

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- reads ---------------------------------------------------------------------------

    def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """The session row as a dict of stored cells, or None when the session is unknown."""
        with self._reader() as store:
            record = store.sessions.get(session_id)
        return record.as_session_row() if record is not None else None

    def get_session_model_config_value(self, session_id: str, key: str, default: Any = None) -> Any:
        with self._reader() as store:
            return store.sessions.get_model_config_value(session_id, key, default)

    def session_ids_with_model_config_key(self, key: str) -> list[str]:
        with self._reader() as store:
            return [sid for sid in store.sessions.session_ids_with_model_config_key(key)]

    def get_session_delete_targets(self, session_id: str) -> list[str]:
        with self._reader() as store:
            return [sid for sid in store.sessions.delete_targets(session_id)]

    # -- writes --------------------------------------------------------------------------

    def patch_session_model_config(self, session_id: str, patch: Mapping[str, Any]) -> None:
        with self._writer() as store:
            store.sessions.patch_model_config(session_id, dict(patch))

    def set_session_hidden(self, session_id: str, hidden: bool) -> bool:
        with self._writer() as store:
            return bool(store.sessions.set_hidden(session_id, bool(hidden)))

    def delete_session(
        self,
        session_id: str,
        *,
        expected_delete_ids: Optional[list[str]] = None,
        exclude_active_write_guards: bool = False,
        include_compression_chain: bool = False,
    ) -> bool:
        """Delete one session's planned lineage, fenced on the ids the caller authorized.

        ``exclude_active_write_guards`` (the pre-0.23 parameter) maps to ``refuse_guarded``:
        a live write lease raises ``SessionWriteGuarded`` instead of deleting, so the burn
        stays pending and a later sweep retries it.
        """
        with self._writer() as store:
            removed = store.sessions.delete(
                session_id,
                expected_ids=list(expected_delete_ids) if expected_delete_ids is not None else None,
                refuse_guarded=bool(exclude_active_write_guards),
                include_compression_chain=include_compression_chain,
                media_root=_media_root(self.db_path),
            )
        return bool(removed)


if open_persistence is None or open_persistence_reader is None or profile_scope is None:
    # No 0.23 storage interface (standalone, pytest, older core): expose None so the
    # engine's existing ``StateStore is None`` guard takes the same no-DB branch that the
    # pre-0.23 fallback exposed when hermes_state was missing.
    StateStore = None  # type: ignore[assignment,misc]
