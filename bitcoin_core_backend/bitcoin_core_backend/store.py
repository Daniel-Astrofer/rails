from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .errors import ApiError


class CohesionStore:
    def __init__(self, path: str, idempotency_ttl_seconds: int) -> None:
        self._path = path
        self._ttl = idempotency_ttl_seconds
        self._lock = threading.RLock()
        self._ensure_parent()
        self._init_db()

    def get_replay(self, key: str, scope: str, request_hash: str) -> tuple[int, dict[str, Any]] | None:
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT scope, request_hash, status_code, response_json
                FROM idempotency_records
                WHERE key = ? AND expires_at > ?
                """,
                (key, now),
            ).fetchone()
        if row is None:
            return None
        if row["scope"] != scope or row["request_hash"] != request_hash:
            raise ApiError(
                409,
                "IDEMPOTENCY_KEY_REUSED",
                "Idempotency-Key was already used for a different request.",
            )
        return int(row["status_code"]), json.loads(row["response_json"])

    def store_response(self, key: str, scope: str, request_hash: str, status_code: int, response: dict[str, Any]) -> None:
        now = int(time.time())
        expires_at = now + self._ttl
        payload = json.dumps(response, sort_keys=True, separators=(",", ":"))
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT scope, request_hash, expires_at FROM idempotency_records WHERE key = ?",
                (key,),
            ).fetchone()
            if (
                row is not None
                and int(row["expires_at"]) > now
                and (row["scope"] != scope or row["request_hash"] != request_hash)
            ):
                raise ApiError(
                    409,
                    "IDEMPOTENCY_KEY_REUSED",
                    "Idempotency-Key was already used for a different request.",
                )
            conn.execute(
                """
                INSERT INTO idempotency_records(key, scope, request_hash, status_code, response_json, created_at, expires_at)
                VALUES(?, ?, ?, ?, ?, strftime('%s','now'), ?)
                ON CONFLICT(key) DO UPDATE SET
                  scope = excluded.scope,
                  request_hash = excluded.request_hash,
                  status_code = excluded.status_code,
                  response_json = excluded.response_json,
                  created_at = excluded.created_at,
                  expires_at = excluded.expires_at
                """,
                (key, scope, request_hash, int(status_code), payload, expires_at),
            )

    def record_transaction(
        self,
        *,
        wallet: str,
        kind: str,
        request_hash: str,
        idempotency_key: str | None,
        outputs: list[dict[str, Any]],
        psbt: str | None = None,
        raw_tx: str | None = None,
        txid: str | None = None,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO transaction_records(
                  wallet, kind, request_hash, idempotency_key, outputs_json,
                  psbt, raw_tx, txid, status, metadata_json, created_at, updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))
                """,
                (
                    wallet,
                    kind,
                    request_hash,
                    idempotency_key,
                    json.dumps(outputs, sort_keys=True, separators=(",", ":")),
                    psbt,
                    raw_tx,
                    txid,
                    status,
                    json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")),
                ),
            )
            return int(cursor.lastrowid)

    def recent_transactions(self, wallet: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 100))
        query = """
            SELECT id, wallet, kind, txid, status, idempotency_key, metadata_json, created_at, updated_at
            FROM transaction_records
        """
        params: tuple[Any, ...] = ()
        if wallet:
            query += " WHERE wallet = ?"
            params = (wallet,)
        query += " ORDER BY id DESC LIMIT ?"
        params = (*params, limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "wallet": row["wallet"],
                "kind": row["kind"],
                "txid": row["txid"],
                "status": row["status"],
                "idempotencyKey": row["idempotency_key"],
                "metadata": json.loads(row["metadata_json"] or "{}"),
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ]

    def summary(self) -> dict[str, Any]:
        with self._connect() as conn:
            tx_count = conn.execute("SELECT count(*) AS value FROM transaction_records").fetchone()["value"]
            idem_count = conn.execute("SELECT count(*) AS value FROM idempotency_records").fetchone()["value"]
        return {"transactionRecords": tx_count, "idempotencyRecords": idem_count}

    def prune_expired(self) -> int:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM idempotency_records WHERE expires_at <= ?", (now,))
            return int(cursor.rowcount)

    def _ensure_parent(self) -> None:
        parent = Path(self._path).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_records (
                  key TEXT PRIMARY KEY,
                  scope TEXT NOT NULL,
                  request_hash TEXT NOT NULL,
                  status_code INTEGER NOT NULL,
                  response_json TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transaction_records (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  wallet TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  request_hash TEXT NOT NULL,
                  idempotency_key TEXT,
                  outputs_json TEXT NOT NULL,
                  psbt TEXT,
                  raw_tx TEXT,
                  txid TEXT,
                  status TEXT NOT NULL,
                  metadata_json TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_wallet_status ON transaction_records(wallet, status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_txid ON transaction_records(txid)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_idem_expires ON idempotency_records(expires_at)")
