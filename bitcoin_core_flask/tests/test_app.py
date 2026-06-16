from __future__ import annotations

import tempfile
import unittest
import importlib.util
from pathlib import Path
import sys

if importlib.util.find_spec("flask") is None:
    raise unittest.SkipTest("Flask is not installed")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app
from config import Settings


class FakeRpcClient:
    def __init__(self):
        self.psbt_calls = 0
        self.wallet_creates = 0

    def node_status(self):
        return {"chain": "regtest", "blocks": 1}

    def list_wallets(self):
        return {"loaded": ["ops"], "available": ["ops"]}

    def create_wallet(self, wallet, disable_private_keys=False, blank=False, descriptors=True):
        self.wallet_creates += 1
        return {"name": wallet}

    def wallet_balance(self, wallet):
        return {"trusted_btc": 1, "untrusted_pending_btc": 0, "immature_btc": 0}

    def new_address(self, wallet, label="", address_type="bech32"):
        return {"address": "bcrt1qexampleaddress00000000000000000000000", "address_type": address_type, "label": label}

    def list_transactions(self, wallet, count=25, skip=0):
        return {"transactions": [{"txid": "a" * 64}], "count": 1, "skip": skip}

    def funded_psbt(self, wallet, outputs, fee_rate_sat_vb=None, lock_unspents=False):
        self.psbt_calls += 1
        return {"psbt": "cHNidP8BAHECAAAAA", "fee_btc": "0.00001000", "change_position": 1}

    def broadcast_raw(self, raw_tx_hex):
        return {"txid": "b" * 64}


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=True)
        self.settings = Settings(
            api_token="x" * 32,
            rpc_url="http://127.0.0.1:18443",
            rpc_user="user",
            rpc_password="password",
            sqlite_path=self.tmp.name,
            rate_limit_per_minute=1000,
        )
        self.rpc = FakeRpcClient()
        self.client = create_app(self.settings, self.rpc).test_client()
        self.headers = {"Authorization": "Bearer " + "x" * 32}

    def test_health_is_public(self):
        response = self.client.get("/health")
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.get_json()["success"])

    def test_auth_required(self):
        response = self.client.get("/v1/wallets")
        self.assertEqual(401, response.status_code)

    def test_wallet_name_validation(self):
        response = self.client.get("/v1/wallets/../../bad/balance", headers=self.headers)
        self.assertIn(response.status_code, {400, 404})

    def test_create_wallet_idempotency(self):
        headers = {**self.headers, "Content-Type": "application/json", "Idempotency-Key": "create-wallet-1"}
        body = {"wallet": "ops"}
        first = self.client.post("/v1/wallets", json=body, headers=headers)
        second = self.client.post("/v1/wallets", json=body, headers=headers)
        self.assertEqual(201, first.status_code)
        self.assertEqual(201, second.status_code)
        self.assertEqual(1, self.rpc.wallet_creates)
        self.assertEqual(first.get_json(), second.get_json())

    def test_idempotency_conflict(self):
        headers = {**self.headers, "Content-Type": "application/json", "Idempotency-Key": "create-wallet-conflict"}
        first = self.client.post("/v1/wallets", json={"wallet": "ops1"}, headers=headers)
        second = self.client.post("/v1/wallets", json={"wallet": "ops2"}, headers=headers)
        self.assertEqual(201, first.status_code)
        self.assertEqual(409, second.status_code)

    def test_psbt_output_validation_and_rpc_shape(self):
        headers = {**self.headers, "Content-Type": "application/json"}
        response = self.client.post(
            "/v1/wallets/ops/transactions/psbt",
            json={
                "outputs": [{"address": "bcrt1qexampleaddress00000000000000000000000", "amount_btc": "0.001"}],
                "fee_rate_sat_vb": 12,
            },
            headers=headers,
        )
        body = response.get_json()
        self.assertEqual(201, response.status_code)
        self.assertEqual("cHNidP8BAHECAAAAA", body["psbt"])
        self.assertEqual(1, self.rpc.psbt_calls)

    def test_rejects_invalid_amount_precision(self):
        headers = {**self.headers, "Content-Type": "application/json"}
        response = self.client.post(
            "/v1/wallets/ops/transactions/psbt",
            json={
                "outputs": [{"address": "bcrt1qexampleaddress00000000000000000000000", "amount_btc": "0.000000001"}]
            },
            headers=headers,
        )
        self.assertEqual(400, response.status_code)

    def test_broadcast_validates_hex(self):
        headers = {**self.headers, "Content-Type": "application/json"}
        response = self.client.post(
            "/v1/wallets/ops/transactions/broadcast",
            json={"raw_tx_hex": "not-hex"},
            headers=headers,
        )
        self.assertEqual(400, response.status_code)


if __name__ == "__main__":
    unittest.main()
