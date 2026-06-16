from __future__ import annotations

import os
from typing import Any

from flask import Flask, g, jsonify, request

from bitcoin_core import BitcoinCoreClient
from cohesion import CohesionStore
from config import Settings
from security import (
    ApiError,
    RateLimiter,
    parse_btc_amount,
    request_fingerprint,
    require_bearer_token,
    require_json_object,
    validate_address,
    validate_tx_hex,
    validate_wallet_name,
)


def create_app(settings: Settings | None = None, rpc_client: BitcoinCoreClient | None = None) -> Flask:
    settings = settings or Settings.from_env()
    settings.validate()

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    app.config["JSON_SORT_KEYS"] = False

    store = CohesionStore(settings.sqlite_path)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    client = rpc_client or BitcoinCoreClient(settings)

    @app.before_request
    def authenticate_and_prepare() -> None:
        if request.path == "/health":
            return
        require_bearer_token(request, settings.api_token)
        limiter.check(request.headers.get("Authorization", "")[-16:] + ":" + request.remote_addr)
        g.idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        g.fingerprint = request_fingerprint(request)
        if request.method in {"POST", "PUT", "PATCH"} and request.content_type:
            if not request.content_type.startswith("application/json"):
                raise ApiError("Content-Type must be application/json", 415, "unsupported_media_type")
        if request.method in {"POST", "PUT", "PATCH"} and g.idempotency_key:
            cached = store.claim_idempotent(g.idempotency_key, g.fingerprint)
            if cached:
                payload, status = cached
                return _json(payload, status)

    @app.errorhandler(ApiError)
    def api_error(error: ApiError):
        return _json({"success": False, "error": {"code": error.code, "message": error.message}}, error.status_code)

    @app.errorhandler(413)
    def too_large(_error):
        return _json({"success": False, "error": {"code": "payload_too_large", "message": "Request body is too large"}}, 413)

    @app.get("/health")
    def health():
        return _json({"success": True, "status": "ok"})

    @app.get("/v1/node/status")
    def node_status():
        return _json({"success": True, "node": client.node_status()})

    @app.get("/v1/wallets")
    def list_wallets():
        return _json({"success": True, "wallets": client.list_wallets()})

    @app.post("/v1/wallets")
    def create_wallet():
        body = require_json_object(request.get_json(silent=True))
        wallet = validate_wallet_name(str(body.get("wallet", "")))
        result = client.create_wallet(
            wallet,
            disable_private_keys=bool(body.get("disable_private_keys", False)),
            blank=bool(body.get("blank", False)),
            descriptors=bool(body.get("descriptors", True)),
        )
        store.append_audit(
            "wallet_created",
            wallet,
            {
                "blank": bool(body.get("blank", False)),
                "descriptors": bool(body.get("descriptors", True)),
                "disable_private_keys": bool(body.get("disable_private_keys", False)),
            },
        )
        return _idempotent({"success": True, "wallet": wallet, "result": result}, 201)

    @app.get("/v1/wallets/<wallet>/balance")
    def wallet_balance(wallet: str):
        wallet = validate_wallet_name(wallet)
        return _json({"success": True, "wallet": wallet, "balance": client.wallet_balance(wallet)})

    @app.post("/v1/wallets/<wallet>/addresses")
    def new_address(wallet: str):
        wallet = validate_wallet_name(wallet)
        body = require_json_object(request.get_json(silent=True) or {})
        result = client.new_address(
            wallet,
            label=str(body.get("label", "")),
            address_type=str(body.get("address_type", "bech32")),
        )
        store.append_audit("address_issued", wallet, {"address_type": result["address_type"], "label": result["label"]})
        return _idempotent({"success": True, "wallet": wallet, **result}, 201)

    @app.get("/v1/wallets/<wallet>/transactions")
    def wallet_transactions(wallet: str):
        wallet = validate_wallet_name(wallet)
        count = _parse_int(request.args.get("count", "25"), "count")
        skip = _parse_int(request.args.get("skip", "0"), "skip")
        return _json({"success": True, "wallet": wallet, **client.list_transactions(wallet, count=count, skip=skip)})

    @app.post("/v1/wallets/<wallet>/transactions/psbt")
    def create_psbt(wallet: str):
        wallet = validate_wallet_name(wallet)
        body = require_json_object(request.get_json(silent=True))
        outputs = _parse_outputs(body.get("outputs"))
        fee_rate = body.get("fee_rate_sat_vb")
        fee_rate_int = _parse_int(fee_rate, "fee_rate_sat_vb") if fee_rate is not None else None
        result = client.funded_psbt(
            wallet,
            outputs,
            fee_rate_sat_vb=fee_rate_int,
            lock_unspents=bool(body.get("lock_unspents", False)),
        )
        store.append_audit("psbt_created", wallet, {"output_count": len(outputs), "fee_rate_sat_vb": fee_rate_int})
        return _idempotent({"success": True, "wallet": wallet, **result}, 201)

    @app.post("/v1/wallets/<wallet>/transactions/broadcast")
    def broadcast(wallet: str):
        wallet = validate_wallet_name(wallet)
        body = require_json_object(request.get_json(silent=True))
        raw_tx_hex = validate_tx_hex(body.get("raw_tx_hex"))
        result = client.broadcast_raw(raw_tx_hex)
        store.append_audit("transaction_broadcast", wallet, {"hex_bytes": len(raw_tx_hex) // 2}, txid=result["txid"])
        return _idempotent({"success": True, "wallet": wallet, **result}, 201)

    @app.get("/v1/cohesion/snapshot")
    def cohesion_snapshot():
        return _json({"success": True, "cohesion": store.snapshot()})

    def _parse_outputs(value: Any) -> list[dict[str, str]]:
        if not isinstance(value, list) or not value:
            raise ApiError("outputs must be a non-empty array", 400, "invalid_outputs")
        if len(value) > 20:
            raise ApiError("outputs may not contain more than 20 entries", 400, "invalid_outputs")
        outputs: list[dict[str, str]] = []
        for entry in value:
            item = require_json_object(entry)
            address = validate_address(item.get("address"))
            amount = parse_btc_amount(item.get("amount_btc"))
            outputs.append({address: amount})
        return outputs

    def _parse_int(value: Any, field: str) -> int:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            raise ApiError(f"{field} must be an integer", 400, "invalid_integer") from None

    def _idempotent(payload: dict[str, Any], status_code: int):
        key = getattr(g, "idempotency_key", "")
        if key:
            store.save_idempotent(key, g.fingerprint, payload, status_code)
        return _json(payload, status_code)

    return app


def _json(payload: dict[str, Any], status_code: int = 200):
    return jsonify(payload), status_code


if __name__ == "__main__":
    create_app().run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8090")))
