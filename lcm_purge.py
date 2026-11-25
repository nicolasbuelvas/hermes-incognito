"""Gate 3b: best-effort purge of a burned incognito session's rows from the LCM store.

Lives outside engine.py so the engine's raw-SQL-delete forensics invariant (state.db rows
are deleted only through SessionDB.delete_session()) holds by construction: every DELETE
in this file targets lcm.db, the hermes-lcm-x plugin's store — never state.db.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def purge_lcm_store(home_dir: Path | str, session_id: str) -> dict[str, Any]:
    """Best-effort delete of *session_id*'s rows from ``<home_dir>/lcm.db``.

    The hermes-lcm-x plugin indexes live turns into lcm.db while a session runs, so a
    burned incognito session otherwise keeps raw, FTS-searchable rows in a store the
    local zero-trace burn never touches. Called at burn time (log-only failure — a busy
    or missing lcm.db must never block the local burn). Mirrors the scrub that swept
    historical orphans 2026-11-21: messages + FTS mirrors (rebuilt), summary nodes +
    provenance, relations, uid bindings, chunks, embeddings, orphaned rollups, and the
    lifecycle-state pointers. Missing tables (schema vintages) are tolerated.
    """
    if not session_id:
        return {"skipped": "no session id"}
    db_path = Path(home_dir) / "lcm.db"
    if not db_path.is_file():
        return {"skipped": "lcm.db not found"}
    result: dict[str, Any] = {"purged_messages": 0, "purged_summaries": 0}
    try:
        con = sqlite3.connect(str(db_path), timeout=15)
        try:
            con.execute("BEGIN IMMEDIATE")

            def run(sql: str, args: tuple = ()) -> int:
                try:
                    cur = con.execute(sql, args)
                    return max(cur.rowcount or 0, 0)
                except sqlite3.OperationalError:
                    return 0  # table absent in this schema vintage

            def query(sql: str, args: tuple = ()) -> list:
                try:
                    return [r[0] for r in con.execute(sql, args).fetchall()]
                except sqlite3.OperationalError:
                    return []  # table absent in this schema vintage

            def ph(count: int) -> str:
                return ",".join("?" * count)

            store_ids = query("SELECT store_id FROM messages WHERE session_id = ?", (session_id,))
            node_ids = query("SELECT node_id FROM summary_nodes WHERE session_id = ?", (session_id,))
            chunk_ids = query(f"SELECT chunk_id FROM lcm_chunk_meta WHERE store_id IN ({ph(len(store_ids))})",
                              store_ids) if store_ids else []

            result["purged_messages"] = run("DELETE FROM messages WHERE session_id = ?", (session_id,))
            result["purged_summaries"] = run("DELETE FROM summary_nodes WHERE session_id = ?", (session_id,))
            if store_ids:
                run(f"DELETE FROM message_relations WHERE store_id IN ({ph(len(store_ids))}) "
                    f"OR related_store_id IN ({ph(len(store_ids))})", tuple(store_ids) * 2)
                run(f"DELETE FROM host_uid_bindings WHERE store_id IN ({ph(len(store_ids))})", tuple(store_ids))
                run(f"DELETE FROM lcm_chunk_meta WHERE store_id IN ({ph(len(store_ids))})", tuple(store_ids))
            if chunk_ids:
                run(f"DELETE FROM lcm_chunk_vectors WHERE chunk_id IN ({ph(len(chunk_ids))})", tuple(chunk_ids))
                run(f"DELETE FROM lcm_chunk_binary WHERE chunk_id IN ({ph(len(chunk_ids))})", tuple(chunk_ids))
            if node_ids:
                run(f"DELETE FROM summary_node_provenance WHERE node_id IN ({ph(len(node_ids))})", tuple(node_ids))
                run(f"DELETE FROM lcm_rollup_invalidations WHERE node_id IN ({ph(len(node_ids))})", tuple(node_ids))
                run(f"DELETE FROM lcm_rollup_sources WHERE node_id IN ({ph(len(node_ids))})", tuple(node_ids))
                orphan_rollups = query(
                    "SELECT r.rollup_id FROM lcm_rollups r "
                    "LEFT JOIN lcm_rollup_sources s ON s.rollup_id = r.rollup_id "
                    "WHERE s.rollup_id IS NULL")
                if orphan_rollups:
                    run(f"DELETE FROM lcm_rollups WHERE rollup_id IN ({ph(len(orphan_rollups))})", tuple(orphan_rollups))
            candidates = [str(x) for x in (store_ids or []) + (chunk_ids or [])]
            if candidates:
                prefixed = ["chunk:" + c for c in candidates]
                emb_ids = query(
                    f"SELECT DISTINCT embedded_id FROM lcm_embedding_vectors "
                    f"WHERE embedded_id IN ({ph(len(candidates))}) OR embedded_id IN ({ph(len(prefixed))})",
                    tuple(candidates + prefixed))
                if emb_ids:
                    run(f"DELETE FROM lcm_embedding_vectors WHERE embedded_id IN ({ph(len(emb_ids))})", tuple(emb_ids))
                    run(f"DELETE FROM lcm_embedding_binary WHERE embedded_id IN ({ph(len(emb_ids))})", tuple(emb_ids))
            if result["purged_messages"]:
                # External-content FTS tables are rebuilt against the (now smaller)
                # content table; per-row deletes would need the old column values.
                run("INSERT INTO messages_fts(messages_fts) VALUES ('rebuild')")
                run("INSERT INTO messages_fts_stem(messages_fts_stem) VALUES ('rebuild')")
            try:
                for cid, cs, ls, cf, lf in con.execute(
                        "SELECT conversation_id, current_session_id, last_finalized_session_id, "
                        "current_frontier_store_id, last_finalized_frontier_store_id "
                        "FROM lcm_lifecycle_state").fetchall():
                    ncf = None if (cf is not None and cf in store_ids) else cf
                    nlf = None if (lf is not None and lf in store_ids) else lf
                    ncs = None if cs == session_id else cs
                    nls = None if ls == session_id else ls
                    if (ncs, nls, ncf, nlf) != (cs, ls, cf, lf):
                        con.execute(
                            "UPDATE lcm_lifecycle_state SET current_session_id = ?, "
                            "last_finalized_session_id = ?, current_frontier_store_id = ?, "
                            "last_finalized_frontier_store_id = ? WHERE conversation_id = ?",
                            (ncs, nls, ncf, nlf, cid))
            except sqlite3.OperationalError:
                pass
            con.commit()
        finally:
            con.close()
        total = result["purged_messages"] + result["purged_summaries"]
        if total:
            logger.info("Incognito burn: purged %d LCM messages + %d summaries for a burned session",
                        result["purged_messages"], result["purged_summaries"])
        return result
    except Exception as exc:
        logger.debug("Incognito LCM purge failed (log-only, burn unaffected): %s", exc)
        return {**result, "error": f"{type(exc).__name__}: {exc}"}
