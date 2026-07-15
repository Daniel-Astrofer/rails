from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SENSITIVE_KEYS = {"macaroon", "payment_request", "paymentRequest", "preimage", "payment_preimage", "token", "secret"}


class CohesionStore:
    def __init__(self, path: str):
        self.path = path
        parent = Path(path).parent
        if parent != Path("."):
            parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS idempotency (
                    key TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lightning_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payment_hash TEXT,
                    amount_sats INTEGER,
                    status TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_lightning_events_created ON lightning_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_lightning_events_payment_hash ON lightning_events(payment_hash);
                """
            )

    def claim_idempotent(self, key: str, fingerprint: str) -> tuple[dict[str, Any], int] | None:
        now = int(time.time())
        with self._conn() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO idempotency(key, fingerprint, status_code, response_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (key, fingerprint, -1, "{}", now),
            )
            inserted = cursor.rowcount == 1
            row = conn.execute(
                "SELECT fingerprint, status_code, response_json, created_at FROM idempotency WHERE key = ?",
                (key,),
            ).fetchone()
        if row["fingerprint"] != fingerprint:
            from security import ApiError

            raise ApiError("Idempotency-Key was reused with a different request", 409, "idempotency_conflict")
        if int(row["status_code"]) == -1:
            if not inserted:
                if now - int(row["created_at"]) > 300:
                    with self._conn() as conn:
                        conn.execute("UPDATE idempotency SET created_at = ? WHERE key = ?", (now, key))
                    return None
                from security import ApiError

                raise ApiError("Request with this Idempotency-Key is still in progress", 409, "idempotency_in_progress")
            return None
        return json.loads(row["response_json"]), int(row["status_code"])

    def save_idempotent(self, key: str, fingerprint: str, response: dict[str, Any], status_code: int) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE idempotency
                SET status_code = ?, response_json = ?
                WHERE key = ? AND fingerprint = ?
                """,
                (status_code, json.dumps(response, separators=(",", ":")), key, fingerprint),
            )

    def append_event(
        self,
        event_type: str,
        *,
        payment_hash: str | None = None,
        amount_sats: int | None = None,
        status: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO lightning_events(event_type, payment_hash, amount_sats, status, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    payment_hash,
                    amount_sats,
                    status,
                    json.dumps(_sanitize(metadata or {}), separators=(",", ":")),
                    int(time.time()),
                ),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._conn() as conn:
            idempotency_count = conn.execute("SELECT COUNT(*) AS count FROM idempotency").fetchone()["count"]
            event_count = conn.execute("SELECT COUNT(*) AS count FROM lightning_events").fetchone()["count"]
            recent = conn.execute(
                """
                SELECT event_type, payment_hash, amount_sats, status, metadata_json, created_at
                FROM lightning_events
                ORDER BY id DESC
                LIMIT 25
                """
            ).fetchall()
        return {
            "idempotency_records": idempotency_count,
            "lightning_events": event_count,
            "recent_events": [
                {
                    "event_type": row["event_type"],
                    "payment_hash": row["payment_hash"],
                    "amount_sats": row["amount_sats"],
                    "status": row["status"],
                    "metadata": json.loads(row["metadata_json"]),
                    "created_at": row["created_at"],
                }
                for row in recent
            ],
        }


def _sanitize(metadata: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metadata.items() if key not in SENSITIVE_KEYS and key.lower() not in SENSITIVE_KEYS}
