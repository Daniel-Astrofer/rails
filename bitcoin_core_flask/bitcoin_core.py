from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from threading import Lock
from typing import Any

from config import Settings
from security import ApiError, validate_wallet_name


class BitcoinCoreClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._rpc_id = 0
        self._lock = Lock()
        self._status_cache: tuple[float, dict[str, Any]] | None = None
        self._base_url = self._validate_url(settings.rpc_url)
        token = f"{settings.rpc_user}:{settings.rpc_password}".encode()
        self._auth_header = "Basic " + base64.b64encode(token).decode("ascii")

    def node_status(self) -> dict[str, Any]:
        cached = self._status_cache
        now = time.monotonic()
        if cached and now - cached[0] <= self.settings.status_cache_seconds:
            return cached[1]
        chain, network, mempool = self.batch(
            [
                ("getblockchaininfo", []),
                ("getnetworkinfo", []),
                ("getmempoolinfo", []),
            ]
        )
        result = {
            "chain": chain.get("chain"),
            "blocks": chain.get("blocks"),
            "headers": chain.get("headers"),
            "verification_progress": chain.get("verificationprogress"),
            "pruned": chain.get("pruned"),
            "difficulty": chain.get("difficulty"),
            "connections": network.get("connections"),
            "version": network.get("version"),
            "mempool_tx_count": mempool.get("size"),
            "mempool_bytes": mempool.get("bytes"),
        }
        self._status_cache = (now, result)
        return result

    def list_wallets(self) -> dict[str, Any]:
        loaded, directory = self.batch([("listwallets", []), ("listwalletdir", [])])
        available = [entry.get("name") for entry in directory.get("wallets", []) if entry.get("name")]
        return {"loaded": loaded, "available": available}

    def create_wallet(
        self,
        wallet: str,
        disable_private_keys: bool = False,
        blank: bool = False,
        descriptors: bool = True,
    ) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet)
        return self.call(
            "createwallet",
            [wallet, bool(disable_private_keys), bool(blank), "", False, bool(descriptors)],
        )

    def wallet_balance(self, wallet: str) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet)
        result = self.call("getbalances", [], wallet=wallet)
        mine = result.get("mine", {})
        return {
            "trusted_btc": mine.get("trusted", 0),
            "untrusted_pending_btc": mine.get("untrusted_pending", 0),
            "immature_btc": mine.get("immature", 0),
        }

    def new_address(self, wallet: str, label: str = "", address_type: str = "bech32") -> dict[str, Any]:
        wallet = validate_wallet_name(wallet)
        if address_type not in {"legacy", "p2sh-segwit", "bech32", "bech32m"}:
            raise ApiError("address_type is invalid", 400, "invalid_address_type")
        if len(label) > 128:
            raise ApiError("label is too long", 400, "invalid_label")
        address = self.call("getnewaddress", [label, address_type], wallet=wallet)
        return {"address": address, "address_type": address_type, "label": label}

    def list_transactions(self, wallet: str, count: int = 25, skip: int = 0) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet)
        count = min(max(int(count), 1), 100)
        skip = max(int(skip), 0)
        txs = self.call("listtransactions", ["*", count, skip, True], wallet=wallet)
        return {"transactions": txs, "count": len(txs), "skip": skip}

    def funded_psbt(
        self,
        wallet: str,
        outputs: list[dict[str, str]],
        fee_rate_sat_vb: int | None = None,
        lock_unspents: bool = False,
    ) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet)
        options: dict[str, Any] = {
            "includeWatching": False,
            "lockUnspents": bool(lock_unspents),
            "replaceable": True,
        }
        if fee_rate_sat_vb is not None:
            if fee_rate_sat_vb < 1 or fee_rate_sat_vb > 10_000:
                raise ApiError("fee_rate_sat_vb is outside allowed range", 400, "invalid_fee_rate")
            options["fee_rate"] = fee_rate_sat_vb
        result = self.call("walletcreatefundedpsbt", [[], outputs, 0, options, True], wallet=wallet)
        return {
            "psbt": result.get("psbt"),
            "fee_btc": result.get("fee"),
            "change_position": result.get("changepos"),
        }

    def broadcast_raw(self, raw_tx_hex: str) -> dict[str, Any]:
        txid = self.call("sendrawtransaction", [raw_tx_hex])
        return {"txid": txid}

    def batch(self, calls: list[tuple[str, list[Any]]]) -> list[Any]:
        payload = []
        with self._lock:
            for method, params in calls:
                self._rpc_id += 1
                payload.append({"jsonrpc": "1.0", "id": self._rpc_id, "method": method, "params": params})
        response = self._request(payload, self._base_url)
        if not isinstance(response, list):
            raise ApiError("Invalid batch RPC response", 502, "rpc_protocol_error")
        response.sort(key=lambda item: item.get("id", 0))
        return [self._unwrap(item) for item in response]

    def call(self, method: str, params: list[Any], wallet: str | None = None) -> Any:
        with self._lock:
            self._rpc_id += 1
            rpc_id = self._rpc_id
        payload = {"jsonrpc": "1.0", "id": rpc_id, "method": method, "params": params}
        endpoint = self._wallet_url(wallet) if wallet else self._base_url
        response = self._request(payload, endpoint)
        return self._unwrap(response)

    def _request(self, payload: Any, endpoint: str) -> Any:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.rpc_timeout_seconds) as response:
                body = response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            body = exc.read(256 * 1024)
            try:
                parsed = json.loads(body.decode("utf-8"))
                message = parsed.get("error", {}).get("message") or "Bitcoin Core RPC rejected request"
            except (json.JSONDecodeError, UnicodeDecodeError):
                message = "Bitcoin Core RPC rejected request"
            raise ApiError(message, 502, "rpc_http_error") from exc
        except urllib.error.URLError as exc:
            raise ApiError("Bitcoin Core RPC is unavailable", 503, "rpc_unavailable") from exc
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError("Bitcoin Core RPC returned invalid JSON", 502, "rpc_protocol_error") from exc

    def _unwrap(self, response: dict[str, Any]) -> Any:
        if not isinstance(response, dict):
            raise ApiError("Invalid RPC response", 502, "rpc_protocol_error")
        error = response.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise ApiError(message or "Bitcoin Core RPC error", 502, "rpc_error")
        return response.get("result")

    def _wallet_url(self, wallet: str | None) -> str:
        if not wallet:
            return self._base_url
        return self._base_url.rstrip("/") + "/wallet/" + urllib.parse.quote(validate_wallet_name(wallet), safe="")

    @staticmethod
    def _validate_url(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("BITCOIN_RPC_URL must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("BITCOIN_RPC_URL must not include credentials, query, or fragment")
        return url.rstrip("/")
