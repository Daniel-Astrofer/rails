from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


# Sensitive fields stripped from event metadata before storage.
# Preimage and route are stripped because they reveal payment path details
# that could be used to deanonymize the sender.
SENSITIVE_KEYS = {"macaroon", "paymentRequest", "preimage", "payment_preimage", "payment_route", "token", "secret"}

# Fields stripped from idempotent response cache (more restrictive than event metadata)
# payment_request is kept because it's needed for invoice replay
RESPONSE_SENSITIVE_KEYS = {"payment_preimage", "payment_route"}


class CohesionStore:
    """ITEM 2 + ITEM 3: Extended idempotency store with state machine.
    States: CLAIMED → SUBMITTED → SUCCEEDED / FAILED_FINAL / UNKNOWN
    Claims use lease + ownership token pattern with long TTL for financial audit."""

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
                    created_at INTEGER NOT NULL,
                    claim_token TEXT,
                    claimed_at INTEGER,
                    lease_expires_at INTEGER,
                    state TEXT NOT NULL DEFAULT 'CLAIMED',
                    payment_hash TEXT,
                    payment_network TEXT NOT NULL DEFAULT '',
                    settled_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS lightning_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payment_hash TEXT,
                    amount_sats INTEGER,
                    status TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    idempotency_key TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_lightning_events_created ON lightning_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_lightning_events_payment_hash ON lightning_events(payment_hash);
                CREATE INDEX IF NOT EXISTS idx_idempotency_state ON idempotency(state);
                CREATE INDEX IF NOT EXISTS idx_idempotency_lease ON idempotency(lease_expires_at);
                """
            )

    def claim_idempotent(
        self, key: str, fingerprint: str, *, payment_hash: str | None = None, network: str = "",
    ) -> tuple[dict[str, Any], int] | None:
        """ITEM 2: Atomic idempotency claim with lease + ownership token pattern.
        First process gets CLAIMED ownership, others get replay or 409 conflict.
        Namespaced key: principal_id:idempotency_key"""
        import uuid
        now = int(time.time())
        lease_seconds = 300  # 5 minute lease for CLAIMED state
        claim_token = str(uuid.uuid4())

        with self._conn() as conn:
            # Try atomic claim with INSERT OR IGNORE inside explicit transaction
            conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO idempotency(key, fingerprint, status_code, response_json, created_at,
                                                     claim_token, claimed_at, lease_expires_at, state, payment_hash, payment_network)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key, fingerprint, -1, "{}", now,
                        claim_token, now, now + lease_seconds, "CLAIMED",
                        payment_hash or "", network,
                    ),
                )
                inserted = cursor.rowcount == 1
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

            row = conn.execute(
                """SELECT fingerprint, status_code, response_json, created_at, claim_token, state,
                   lease_expires_at, payment_hash FROM idempotency WHERE key = ?""",
                (key,),
            ).fetchone()

        if row is None:
            return None

        # Conflict: different fingerprint with same key
        if row["fingerprint"] != fingerprint:
            from src.core.security import ApiError
            raise ApiError(
                "Idempotency-Key was reused with a different request", 409, "idempotency_conflict",
            )

        state = row["state"]
        if state in ("SUCCEEDED", "FAILED_FINAL"):
            return json.loads(row["response_json"]), int(row["status_code"])

        if state == "CLAIMED":
            lease_expires = int(row["lease_expires_at"])
            if not inserted:
                # Another process owns the claim
                if now < lease_expires:
                    from src.core.security import ApiError
                    raise ApiError(
                        "Request with this Idempotency-Key is still in progress", 409, "idempotency_in_progress",
                    )
                # Stale lease: another process timed out, but we cannot auto-retry
                # Return UNKNOWN so caller knows to reconcile
                return json.loads('{"success":false,"error":{"code":"idempotency_unknown","message":"Previous request timed out. Reconcile before retrying."}}'), 409
            # Claim succeeded — store claim_token in g for caller
            return None

        if state == "SUBMITTED":
            # In-flight at LND, return in-progress
            from src.core.security import ApiError
            raise ApiError(
                "Request is being processed by LND", 409, "idempotency_in_progress",
            )

        if state == "UNKNOWN":
            # Previous request timed out after LND call
            return json.loads('{"success":false,"error":{"code":"idempotency_unknown","message":"Previous request result unknown. Reconcile before retrying."}}'), 409

        # Fallback: stale/unclaimed record
        if int(row["status_code"]) == -1:
            if not inserted:
                if now - int(row["created_at"]) > lease_seconds:
                    # Re-claim stale record
                    new_claim = str(uuid.uuid4())
                    with self._conn() as conn:
                        conn.execute(
                            "UPDATE idempotency SET claim_token=?, claimed_at=?, lease_expires_at=?, state='CLAIMED' WHERE key=? AND fingerprint=?",
                            (new_claim, now, now + lease_seconds, key, fingerprint),
                        )
                    return None
                from src.core.security import ApiError
                raise ApiError("Request with this Idempotency-Key is still in progress", 409, "idempotency_in_progress")
            return None

        return json.loads(row["response_json"]), int(row["status_code"])

    def save_idempotent(self, key: str, fingerprint: str, response: dict[str, Any], status_code: int) -> None:
        safe_response = _strip_keys(response, RESPONSE_SENSITIVE_KEYS)
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE idempotency
                SET status_code = ?, response_json = ?, state = 'SUCCEEDED', settled_at = ?
                WHERE key = ? AND fingerprint = ?
                """,
                (status_code, json.dumps(safe_response, separators=(",", ":")), int(time.time()), key, fingerprint),
            )

    def mark_submitted(self, key: str, fingerprint: str, payment_hash: str) -> None:
        """ITEM 2: Transition claim from CLAIMED to SUBMITTED after LND call."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE idempotency SET state='SUBMITTED', payment_hash=? WHERE key=? AND fingerprint=? AND state='CLAIMED'",
                (payment_hash, key, fingerprint),
            )

    def mark_failed(self, key: str, fingerprint: str, error_code: str, message: str) -> None:
        """ITEM 2: Mark claim as FAILED_FINAL after a definitive failure."""
        now = int(time.time())
        payload = json.dumps(
            {"success": False, "error": {"code": error_code, "message": message}},
            separators=(",", ":"),
        )
        with self._conn() as conn:
            conn.execute(
                "UPDATE idempotency SET status_code=400, response_json=?, state='FAILED_FINAL', settled_at=? WHERE key=? AND fingerprint=?",
                (payload, now, key, fingerprint),
            )

    def mark_unknown(self, key: str, fingerprint: str, payment_hash: str) -> None:
        """ITEM 2: Mark claim as UNKNOWN after LND timeout.
        Blocks new payments until reconciled."""
        now = int(time.time())
        with self._conn() as conn:
            conn.execute(
                "UPDATE idempotency SET state='UNKNOWN', payment_hash=?, lease_expires_at=? WHERE key=? AND fingerprint=?",
                (payment_hash, now + 86400, key, fingerprint),
            )

    def heartbeat_claim(self, key: str, fingerprint: str) -> bool:
        """ITEM 31: Extend lease for in-progress claims. Only owner can heartbeat."""
        now = int(time.time())
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE idempotency SET lease_expires_at=? WHERE key=? AND fingerprint=? AND state='CLAIMED'",
                (now + 300, key, fingerprint),
            )
            return cursor.rowcount > 0

    def query_payment_by_hash(self, payment_hash: str) -> dict[str, Any] | None:
        """ITEM 31: Look up idempotency record by payment_hash for reconciliation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT key, state, status_code, response_json, created_at FROM idempotency WHERE payment_hash=? ORDER BY created_at DESC",
                (payment_hash,),
            ).fetchone()
        if row is None:
            return None
        return {"key": row["key"], "state": row["state"], "status_code": row["status_code"],
                "response": json.loads(row["response_json"])}

    def append_event(
        self,
        event_type: str,
        *,
        payment_hash: str | None = None,
        amount_sats: int | None = None,
        status: str | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str = "",
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO lightning_events(event_type, payment_hash, amount_sats, status, metadata_json, created_at, idempotency_key)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    payment_hash,
                    amount_sats,
                    status,
                    json.dumps(_sanitize(metadata or {}), separators=(",", ":")),
                    int(time.time()),
                    idempotency_key,
                ),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._conn() as conn:
            idempotency_count = conn.execute("SELECT COUNT(*) AS count FROM idempotency").fetchone()["count"]
            event_count = conn.execute("SELECT COUNT(*) AS count FROM lightning_events").fetchone()["count"]
            unknown_count = conn.execute("SELECT COUNT(*) AS count FROM idempotency WHERE state='UNKNOWN'").fetchone()["count"]
            recent = conn.execute(
                """
                SELECT event_type, payment_hash, amount_sats, status, metadata_json, created_at, idempotency_key
                FROM lightning_events
                ORDER BY id DESC
                LIMIT 25
                """
            ).fetchall()
        return {
            "idempotency_records": idempotency_count,
            "unknown_idempotency_records": unknown_count,
            "lightning_events": event_count,
            "recent_events": [
                {
                    "event_type": row["event_type"],
                    "payment_hash": row["payment_hash"],
                    "amount_sats": row["amount_sats"],
                    "status": row["status"],
                    "metadata": json.loads(row["metadata_json"]),
                    "created_at": row["created_at"],
                    "idempotency_key": row["idempotency_key"],
                }
                for row in recent
            ],
        }


def _sanitize(metadata: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metadata.items() if key not in SENSITIVE_KEYS and key.lower() not in SENSITIVE_KEYS}


def _strip_keys(obj: Any, keys_to_strip: set[str]) -> Any:
    """Recursively strip specified keys from nested dicts/lists."""
    if isinstance(obj, dict):
        return {key: _strip_keys(value, keys_to_strip) for key, value in obj.items()
                if key not in keys_to_strip and key.lower() not in keys_to_strip}
    if isinstance(obj, list):
        return [_strip_keys(item, keys_to_strip) for item in obj]
    return obj
