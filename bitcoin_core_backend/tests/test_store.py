import tempfile
import unittest
from unittest.mock import patch

from bitcoin_core_backend.errors import ApiError
from bitcoin_core_backend.store import CohesionStore


class CohesionStoreTests(unittest.TestCase):
    def test_idempotency_replay_and_conflict(self):
        with tempfile.NamedTemporaryFile() as tmp:
            store = CohesionStore(tmp.name, idempotency_ttl_seconds=3600)
            store.store_response("request-000001", "POST:/v1/a", "hash-a", 200, {"success": True})

            self.assertEqual(
                store.get_replay("request-000001", "POST:/v1/a", "hash-a"),
                (200, {"success": True}),
            )
            with self.assertRaises(ApiError):
                store.get_replay("request-000001", "POST:/v1/a", "hash-b")

    def test_expired_idempotency_key_can_be_reused_for_new_scope(self):
        with tempfile.NamedTemporaryFile() as tmp:
            store = CohesionStore(tmp.name, idempotency_ttl_seconds=1)
            with patch("bitcoin_core_backend.store.time.time", return_value=1000):
                store.store_response("request-000001", "POST:/v1/a", "hash-a", 200, {"route": "a"})

            with patch("bitcoin_core_backend.store.time.time", return_value=1002):
                self.assertIsNone(store.get_replay("request-000001", "POST:/v1/a", "hash-a"))
                store.store_response("request-000001", "POST:/v1/b", "hash-b", 201, {"route": "b"})
                self.assertEqual(
                    store.get_replay("request-000001", "POST:/v1/b", "hash-b"),
                    (201, {"route": "b"}),
                )
                with self.assertRaises(ApiError):
                    store.get_replay("request-000001", "POST:/v1/a", "hash-a")

    def test_transaction_summary(self):
        with tempfile.NamedTemporaryFile() as tmp:
            store = CohesionStore(tmp.name, idempotency_ttl_seconds=3600)
            record_id = store.record_transaction(
                wallet="main",
                kind="psbt",
                request_hash="hash",
                idempotency_key=None,
                outputs=[{"address": "bc1qexample", "amountSats": 1}],
                status="created",
            )
            self.assertGreater(record_id, 0)
            self.assertEqual(store.summary()["transactionRecords"], 1)
            self.assertEqual(store.recent_transactions("main")[0]["status"], "created")


if __name__ == "__main__":
    unittest.main()
