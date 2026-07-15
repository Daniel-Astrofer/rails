from __future__ import annotations

import os
from typing import Any

from flask import Flask, g, jsonify, request

from cohesion import CohesionStore
from config import Settings
from lnd import LndClient
from security import (
    ApiError,
    RateLimiter,
    parse_optional_int,
    parse_sats,
    request_fingerprint,
    require_bearer_token,
    require_json_object,
    validate_bolt11,
    validate_memo,
    validate_payment_hash,
)


def create_app(settings: Settings | None = None, lnd_client: LndClient | None = None) -> Flask:
    settings = settings or Settings.from_env()
    settings.validate()

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    app.config["JSON_SORT_KEYS"] = False

    store = CohesionStore(settings.sqlite_path)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    client = lnd_client or LndClient(settings)

    @app.before_request
    def authenticate_and_prepare():
        if request.path == "/health":
            return None
        require_bearer_token(request, settings.api_token)
        limiter.check(request.headers.get("Authorization", "")[-16:] + ":" + str(request.remote_addr))
        g.idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        g.fingerprint = request_fingerprint(request)
        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.content_type or ""
            if not content_type.startswith("application/json"):
                raise ApiError("Content-Type must be application/json", 415, "unsupported_media_type")
        if request.method in {"POST", "PUT", "PATCH"} and g.idempotency_key:
            cached = store.claim_idempotent(g.idempotency_key, g.fingerprint)
            if cached:
                payload, status = cached
                return _json(payload, status)
        return None

    @app.after_request
    def set_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(ApiError)
    def api_error(error: ApiError):
        return _json({"success": False, "error": {"code": error.code, "message": error.message}}, error.status_code)

    @app.errorhandler(413)
    def too_large(_error):
        return _json({"success": False, "error": {"code": "payload_too_large", "message": "Request body is too large"}}, 413)

    @app.errorhandler(Exception)
    def unhandled(error: Exception):
        app.logger.exception("Unhandled Lightning backend error")
        return _json({"success": False, "error": {"code": "internal_error", "message": "Internal server error"}}, 500)

    @app.get("/health")
    def health():
        return _json({"success": True, "status": "ok"})

    @app.get("/v1/node/status")
    def node_status():
        return _json({"success": True, "node": client.node_status()})

    @app.get("/v1/channels")
    def channels():
        return _json({"success": True, **client.list_channels()})

    @app.post("/v1/invoices")
    def create_invoice():
        body = require_json_object(request.get_json(silent=True))
        amount_sats = parse_sats(body.get("amount_sats"), "amount_sats", settings.max_invoice_sats)
        memo = validate_memo(body.get("memo", ""))
        expiry_seconds = parse_optional_int(
            body.get("expiry_seconds"),
            "expiry_seconds",
            settings.default_invoice_expiry_seconds,
            60,
            2_592_000,
        )
        result = client.create_invoice(amount_sats, memo, expiry_seconds)
        store.append_event(
            "invoice_created",
            payment_hash=result.get("payment_hash"),
            amount_sats=amount_sats,
            status="open",
            metadata={"memo": memo, "expiry_seconds": expiry_seconds},
        )
        return _idempotent({"success": True, "invoice": result}, 201)

    @app.get("/v1/invoices/<payment_hash>")
    def lookup_invoice(payment_hash: str):
        payment_hash = validate_payment_hash(payment_hash)
        return _json({"success": True, "invoice": client.lookup_invoice(payment_hash)})

    @app.post("/v1/payments")
    def pay_invoice():
        body = require_json_object(request.get_json(silent=True))
        payment_request = validate_bolt11(body.get("payment_request"))
        fee_limit_sats = parse_optional_int(body.get("fee_limit_sats"), "fee_limit_sats", 50, 1, 1_000_000)
        timeout_seconds = parse_optional_int(body.get("timeout_seconds"), "timeout_seconds", 60, 1, 600)
        result = client.pay_invoice(payment_request, fee_limit_sats, timeout_seconds)
        store.append_event(
            "payment_submitted",
            payment_hash=result.get("payment_hash"),
            status=result.get("status"),
            metadata={"fee_limit_sats": fee_limit_sats, "timeout_seconds": timeout_seconds},
        )
        return _idempotent({"success": True, "payment": result}, 202)

    @app.get("/v1/payments/<payment_hash>")
    def lookup_payment(payment_hash: str):
        payment_hash = validate_payment_hash(payment_hash)
        return _json({"success": True, "payment": client.lookup_payment(payment_hash)})

    @app.get("/v1/cohesion/snapshot")
    def cohesion_snapshot():
        return _json({"success": True, "cohesion": store.snapshot()})

    def _idempotent(payload: dict[str, Any], status_code: int):
        key = getattr(g, "idempotency_key", "")
        if key:
            store.save_idempotent(key, g.fingerprint, payload, status_code)
        return _json(payload, status_code)

    return app


def _json(payload: dict[str, Any], status_code: int = 200):
    return jsonify(payload), status_code


if __name__ == "__main__":
    create_app().run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8091")))
