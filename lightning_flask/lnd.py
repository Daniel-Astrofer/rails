from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from config import Settings
from security import ApiError, validate_payment_hash


class LndClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._base_url = self._validate_url(settings.lnd_rest_url)
        self._macaroon_hex = settings.lnd_macaroon_hex or self._read_macaroon(settings.lnd_macaroon_path)
        self._ssl_context = self._ssl_context(settings.lnd_tls_cert_path)
        self._status_cache: tuple[float, dict[str, Any]] | None = None

    def node_status(self) -> dict[str, Any]:
        cached = self._status_cache
        now = time.monotonic()
        if cached and now - cached[0] <= self.settings.status_cache_seconds:
            return cached[1]
        info = self.get("/v1/getinfo")
        wallet_balance = self.get("/v1/balance/blockchain")
        channel_balance = self.get("/v1/balance/channels")
        result = {
            "identity_pubkey": info.get("identity_pubkey"),
            "alias": info.get("alias"),
            "version": info.get("version"),
            "synced_to_chain": bool(info.get("synced_to_chain")),
            "synced_to_graph": bool(info.get("synced_to_graph")),
            "block_height": _as_int(info.get("block_height")),
            "num_active_channels": _as_int(info.get("num_active_channels")),
            "num_pending_channels": _as_int(info.get("num_pending_channels")),
            "num_peers": _as_int(info.get("num_peers")),
            "wallet_confirmed_balance_sats": _as_int(wallet_balance.get("confirmed_balance")),
            "channel_local_balance_sats": _as_int(channel_balance.get("local_balance", {}).get("sat")),
            "channel_remote_balance_sats": _as_int(channel_balance.get("remote_balance", {}).get("sat")),
        }
        self._status_cache = (now, result)
        return result

    def create_invoice(self, amount_sats: int, memo: str, expiry_seconds: int) -> dict[str, Any]:
        result = self.post(
            "/v1/invoices",
            {
                "value": str(amount_sats),
                "memo": memo,
                "expiry": str(expiry_seconds),
                "private": True,
            },
        )
        payment_hash = _hash_to_hex(result.get("r_hash")) or result.get("r_hash_str")
        return {
            "payment_hash": payment_hash,
            "payment_request": result.get("payment_request"),
            "add_index": result.get("add_index"),
            "amount_sats": amount_sats,
            "memo": memo,
            "expiry_seconds": expiry_seconds,
        }

    def lookup_invoice(self, payment_hash: str) -> dict[str, Any]:
        payment_hash = validate_payment_hash(payment_hash)
        result = self.get(f"/v1/invoice/{payment_hash}")
        return _invoice_view(result, fallback_hash=payment_hash)

    def pay_invoice(self, payment_request: str, fee_limit_sats: int, timeout_seconds: int) -> dict[str, Any]:
        result = self.post(
            "/v1/channels/transactions",
            {
                "payment_request": payment_request,
                "fee_limit": {"fixed": str(fee_limit_sats)},
                "timeout_seconds": timeout_seconds,
            },
        )
        payment_hash = result.get("payment_hash") or _hash_to_hex(result.get("payment_hash_bytes"))
        return {
            "payment_hash": payment_hash,
            "payment_preimage": result.get("payment_preimage"),
            "payment_route": result.get("payment_route"),
            "payment_error": result.get("payment_error"),
            "status": "failed" if result.get("payment_error") else "submitted",
            "fee_limit_sats": fee_limit_sats,
        }

    def lookup_payment(self, payment_hash: str) -> dict[str, Any]:
        payment_hash = validate_payment_hash(payment_hash)
        result = self.get("/v1/payments", {"include_incomplete": "true", "payment_hash": payment_hash})
        payments = result.get("payments") if isinstance(result, dict) else None
        if isinstance(payments, list) and payments:
            payment = payments[0]
            return {
                "payment_hash": payment.get("payment_hash", payment_hash),
                "status": payment.get("status"),
                "value_sats": _as_int(payment.get("value_sat")),
                "fee_sats": _as_int(payment.get("fee_sat")),
                "creation_time_ns": payment.get("creation_time_ns"),
            }
        return {"payment_hash": payment_hash, "status": "unknown"}

    def list_channels(self) -> dict[str, Any]:
        result = self.get("/v1/channels")
        channels = result.get("channels", []) if isinstance(result, dict) else []
        return {
            "channels": [
                {
                    "active": bool(channel.get("active")),
                    "remote_pubkey": channel.get("remote_pubkey"),
                    "channel_point": channel.get("channel_point"),
                    "capacity_sats": _as_int(channel.get("capacity")),
                    "local_balance_sats": _as_int(channel.get("local_balance")),
                    "remote_balance_sats": _as_int(channel.get("remote_balance")),
                }
                for channel in channels
            ]
        }

    def get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, query=query)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", path, body=body)

    def _request(self, method: str, path: str, query: dict[str, Any] | None = None, body: dict[str, Any] | None = None) -> Any:
        url = self._base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Grpc-Metadata-macaroon": self._macaroon_hex,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.lnd_timeout_seconds, context=self._ssl_context) as response:
                raw = response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            raw = exc.read(256 * 1024)
            message = "LND rejected request"
            try:
                parsed = json.loads(raw.decode("utf-8"))
                message = parsed.get("error") or parsed.get("message") or message
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            raise ApiError(str(message), 502, "lnd_http_error") from exc
        except urllib.error.URLError as exc:
            raise ApiError("LND REST API is unavailable", 503, "lnd_unavailable") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError("LND REST API returned invalid JSON", 502, "lnd_protocol_error") from exc

    @staticmethod
    def _validate_url(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("LIGHTNING_LND_REST_URL must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("LIGHTNING_LND_REST_URL must not include credentials, query, or fragment")
        return url.rstrip("/")

    @staticmethod
    def _read_macaroon(path: str) -> str:
        try:
            return Path(path).read_bytes().hex()
        except OSError as exc:
            raise ValueError("Unable to read LIGHTNING_LND_MACAROON_PATH") from exc

    @staticmethod
    def _ssl_context(cert_path: str) -> ssl.SSLContext | None:
        if not cert_path:
            return None
        return ssl.create_default_context(cafile=cert_path)


def _hash_to_hex(value: Any) -> str | None:
    if not value:
        return None
    try:
        return base64.b64decode(str(value), validate=True).hex()
    except (ValueError, TypeError):
        text = str(value)
        return text.lower() if len(text) == 64 else None


def _invoice_view(result: dict[str, Any], fallback_hash: str) -> dict[str, Any]:
    settled = bool(result.get("settled"))
    return {
        "payment_hash": result.get("r_hash_str") or _hash_to_hex(result.get("r_hash")) or fallback_hash,
        "payment_request": result.get("payment_request"),
        "memo": result.get("memo"),
        "amount_sats": _as_int(result.get("value")),
        "amount_paid_sats": _as_int(result.get("amt_paid_sat")),
        "state": result.get("state") or ("SETTLED" if settled else "OPEN"),
        "settled": settled,
        "creation_date": result.get("creation_date"),
        "settle_date": result.get("settle_date"),
        "expiry": result.get("expiry"),
    }


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
