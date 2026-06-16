from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

if importlib.util.find_spec("flask") is None:
    raise unittest.SkipTest("Flask is not installed")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app
from config import Settings


PAYMENT_HASH = "a" * 64
INVOICE = "lnbc1" + "p" * 80


class FakeLndClient:
    def __init__(self):
        self.invoice_calls = 0
        self.payment_calls = 0

    def node_status(self):
        return {"alias": "kerosene-lnd", "synced_to_chain": True, "block_height": 100}

    def list_channels(self):
        return {"channels": [{"active": True, "remote_pubkey": "02" + "b" * 64, "capacity_sats": 1000}]}

    def create_invoice(self, amount_sats, memo, expiry_seconds):
        self.invoice_calls += 1
        return {
            "payment_hash": PAYMENT_HASH,
            "payment_request": INVOICE,
            "amount_sats": amount_sats,
            "memo": memo,
            "expiry_seconds": expiry_seconds,
        }

    def lookup_invoice(self, payment_hash):
        return {"payment_hash": payment_hash, "amount_sats": 2500, "state": "OPEN", "settled": False}

    def pay_invoice(self, payment_request, fee_limit_sats, timeout_seconds):
        self.payment_calls += 1
        return {
            "payment_hash": PAYMENT_HASH,
            "payment_preimage": "secret-preimage",
            "status": "submitted",
            "fee_limit_sats": fee_limit_sats,
        }

    def lookup_payment(self, payment_hash):
        return {"payment_hash": payment_hash, "status": "SUCCEEDED", "fee_sats": 2}


class LightningAppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=True)
        self.settings = Settings(
            api_token="x" * 32,
            lnd_rest_url="https://127.0.0.1:8080",
            lnd_macaroon_hex="00" * 32,
            sqlite_path=self.tmp.name,
            rate_limit_per_minute=1000,
            max_invoice_sats=100_000,
            max_payment_sats=100_000,
        )
        self.lnd = FakeLndClient()
        self.client = create_app(self.settings, self.lnd).test_client()
        self.headers = {"Authorization": "Bearer " + "x" * 32}

    def test_health_is_public(self):
        response = self.client.get("/health")
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.get_json()["success"])

    def test_auth_required(self):
        response = self.client.get("/v1/node/status")
        self.assertEqual(401, response.status_code)

    def test_status_and_security_headers(self):
        response = self.client.get("/v1/node/status", headers=self.headers)
        body = response.get_json()
        self.assertEqual(200, response.status_code)
        self.assertEqual("kerosene-lnd", body["node"]["alias"])
        self.assertEqual("no-store", response.headers["Cache-Control"])
        self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])

    def test_create_invoice_idempotency(self):
        headers = {**self.headers, "Content-Type": "application/json", "Idempotency-Key": "invoice-1"}
        body = {"amount_sats": 2500, "memo": "coffee", "expiry_seconds": 600}
        first = self.client.post("/v1/invoices", json=body, headers=headers)
        second = self.client.post("/v1/invoices", json=body, headers=headers)
        self.assertEqual(201, first.status_code)
        self.assertEqual(201, second.status_code)
        self.assertEqual(first.get_json(), second.get_json())
        self.assertEqual(1, self.lnd.invoice_calls)

    def test_idempotency_conflict(self):
        headers = {**self.headers, "Content-Type": "application/json", "Idempotency-Key": "invoice-conflict"}
        first = self.client.post("/v1/invoices", json={"amount_sats": 1000}, headers=headers)
        second = self.client.post("/v1/invoices", json={"amount_sats": 2000}, headers=headers)
        self.assertEqual(201, first.status_code)
        self.assertEqual(409, second.status_code)

    def test_invoice_amount_validation(self):
        headers = {**self.headers, "Content-Type": "application/json"}
        response = self.client.post("/v1/invoices", json={"amount_sats": 100_001}, headers=headers)
        self.assertEqual(400, response.status_code)

    def test_pay_invoice_validation_and_audit_sanitization(self):
        headers = {**self.headers, "Content-Type": "application/json", "Idempotency-Key": "pay-1"}
        response = self.client.post(
            "/v1/payments",
            json={"payment_request": INVOICE, "fee_limit_sats": 10, "timeout_seconds": 30},
            headers=headers,
        )
        self.assertEqual(202, response.status_code)
        self.assertEqual(1, self.lnd.payment_calls)

        snapshot = self.client.get("/v1/cohesion/snapshot", headers=self.headers).get_json()["cohesion"]
        self.assertEqual(1, snapshot["lightning_events"])
        metadata = snapshot["recent_events"][0]["metadata"]
        self.assertNotIn("payment_request", metadata)
        self.assertNotIn("payment_preimage", metadata)

    def test_rejects_invalid_bolt11(self):
        headers = {**self.headers, "Content-Type": "application/json"}
        response = self.client.post("/v1/payments", json={"payment_request": "not-an-invoice"}, headers=headers)
        self.assertEqual(400, response.status_code)

    def test_lookup_payment_hash_validation(self):
        response = self.client.get("/v1/payments/nothex", headers=self.headers)
        self.assertEqual(400, response.status_code)


if __name__ == "__main__":
    unittest.main()
