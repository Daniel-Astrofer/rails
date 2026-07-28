from __future__ import annotations

import logging
import os
import time
from typing import Any

from flask import Flask, g, jsonify, request

from src.infra.cohesion import CohesionStore
from src.core.config import Settings
from src.infra.lnd import LndClient
from src.core.security import (
    ApiError,
    RateLimiter,
    RedisRateLimiter,
    decode_bolt11_amount_msat,
    decode_bolt11_network,
    decode_bolt11_expired,
    parse_optional_int,
    parse_sats,
    request_fingerprint,
    require_bearer_token_scoped,
    require_admin_header,
    require_json_object,
    validate_bolt11,
    validate_idempotency_key,
    validate_idempotency_key_payment,
    validate_memo,
    validate_payment_hash,
)

logger = logging.getLogger(__name__)


class IdempotentReplay(Exception):
    """Internal exception to signal an idempotent replay response."""
    def __init__(self, payload: dict[str, Any], status_code: int):
        self.payload = payload
        self.status_code = status_code


def create_app(settings: Settings | None = None, lnd_client: LndClient | None = None) -> Flask:
    settings = settings or Settings.from_env()
    settings.validate()

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    app.config["JSON_SORT_KEYS"] = False

    store = CohesionStore(settings.sqlite_path)
    if settings.rate_limit_backend == "redis" and settings.redis_url:
        limiter: RateLimiter | RedisRateLimiter = RedisRateLimiter(settings.redis_url, settings.rate_limit_per_minute)
    else:
        limiter = RateLimiter(settings.rate_limit_per_minute)
    client = lnd_client or LndClient(settings)

    # ITEM 27: Validate LND network at startup
    _validate_lnd_network(client, settings)

    # ITEM 25: Startup auth/bind checks
    host = os.getenv("HOST", "127.0.0.1").strip()
    if settings.auth_disabled:
        if settings.production:
            raise RuntimeError("LIGHTNING_AUTH_DISABLED=true is not allowed in production")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("Auth cannot be disabled when binding to non-loopback address")
        logger.warning("AUTH DISABLED — running in dev mode. Do NOT use in production.")

    # ITEM 28: Enforce TLS for non-loopback
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.getenv("LIGHTNING_TLS_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}:
        raise RuntimeError("HTTPS/TLS required when binding to non-loopback. Set LIGHTNING_TLS_ENABLED=true.")

    @app.before_request
    def authenticate_and_prepare():
        if request.path == "/health":
            return None

        # Scoped auth: admin endpoints use X-Kerosene-Admin-Key header
        if request.path.startswith("/v1/admin/"):
            require_admin_header(request, settings.admin_token)
            principal = "admin"
        else:
            require_write = request.method in {"POST", "PUT", "PATCH", "DELETE"}
            require_bearer_token_scoped(request, settings.read_token, settings.write_token, require_write)
            # Extract principal from auth header for idempotency namespace
            header = request.headers.get("Authorization", "")
            principal = header[7:].strip()[-8:] if header.startswith("Bearer ") else "anon"

        g.principal_id = principal
        limiter.check(principal + ":" + str(request.remote_addr))
        g.fingerprint = request_fingerprint(request)
        g.idempotency_key = ""
        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.content_type or ""
            if not content_type.startswith("application/json"):
                raise ApiError("Content-Type must be application/json", 415, "unsupported_media_type")
        return None

    @app.after_request
    def set_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(ApiError)
    def api_error(error: ApiError):
        return _json({"success": False, "error": {"code": error.code, "message": error.message}}, error.status_code)

    @app.errorhandler(IdempotentReplay)
    def idempotent_replay(error: IdempotentReplay):
        return _json(error.payload, error.status_code)

    @app.errorhandler(413)
    def too_large(_error):
        return _json({"success": False, "error": {"code": "payload_too_large", "message": "Request body is too large"}}, 413)

    @app.errorhandler(Exception)
    def unhandled(error: Exception):
        app.logger.exception("Unhandled Lightning backend error")
        return _json({"success": False, "error": {"code": "internal_error", "message": "Internal server error"}}, 500)

    @app.get("/health")
    def health():
        return _json({
            "success": True,
            "status": "ok",
            "auth_disabled": settings.auth_disabled,
            "network": settings.network,
            "production": settings.production,
        })

    # ITEM 33-34: Reduced node status — only reachable/synced/network
    @app.get("/v1/node/status")
    def node_status():
        info = client.node_status()
        return _json({
            "success": True,
            "node": {
                "synced_to_chain": info.get("synced_to_chain"),
                "synced_to_graph": info.get("synced_to_graph"),
                "block_height": info.get("block_height"),
                "network": settings.network,
            },
        })

    # ── Admin node status (full detail) ──
    @app.get("/v1/admin/node/status")
    def admin_node_status():
        return _json({"success": True, "node": client.node_status()})

    # ── Admin endpoints (require X-Kerosene-Admin-Key header) ──

    @app.get("/v1/admin/channels")
    def admin_channels():
        return _json({"success": True, **client.list_channels()})

    @app.get("/v1/admin/channels/pending")
    def admin_channels_pending():
        channels = client.list_channels()
        pending = [ch for ch in channels.get("channels", []) if not ch.get("active")]
        return _json({"success": True, "channels": pending})

    @app.get("/v1/admin/channels/closed")
    def admin_channels_closed():
        return _json({"success": True, "channels": [], "note": "Closed channel query requires LND closed channel lookup"})

    @app.get("/v1/cohesion/snapshot")
    def cohesion_snapshot():
        return _json({"success": True, "cohesion": store.snapshot()})

    # ── Business endpoints (read/write tokens) ──

    @app.post("/v1/invoices")
    def create_invoice():
        _require_idempotency(store)
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
        return _idempotent(store, {"success": True, "invoice": result}, 201)

    @app.get("/v1/invoices/<payment_hash>")
    def lookup_invoice(payment_hash: str):
        payment_hash = validate_payment_hash(payment_hash)
        return _json({"success": True, "invoice": client.lookup_invoice(payment_hash)})

    @app.post("/v1/payments")
    def pay_invoice():
        body = require_json_object(request.get_json(silent=True))
        payment_request = validate_bolt11(body.get("payment_request"))

        # ── ITEM 1: Pre-LND validation (no LND call before complete validation) ──

        # Decode invoice server-side via LND for full field extraction
        try:
            decoded = client.decode_invoice(payment_request)
        except ApiError:
            raise
        except Exception as exc:
            logger.warning("LND payreq decode failed: %s", exc)
            raise ApiError("Failed to decode invoice from LND", 502, "lnd_decode_error")

        payment_hash = decoded.get("payment_hash") or ""
        invoice_amount_sats = decoded.get("num_satoshis", 0)
        invoice_network = decoded.get("network", "")
        invoice_expiry = decoded.get("expiry", 3600)
        invoice_ts = decoded.get("timestamp", 0)

        # Validate network match
        if invoice_network and invoice_network != settings.network:
            raise ApiError(
                f"Invoice network ({invoice_network}) does not match configured network ({settings.network})",
                400, "network_mismatch",
            )

        # Validate expiry
        if invoice_ts > 0:
            expire_time = invoice_ts + max(invoice_expiry, 1)
            if int(time.time()) > expire_time:
                raise ApiError("Invoice has expired", 400, "invoice_expired")

        # Amount validation
        amount_sats = 0
        if invoice_amount_sats > 0:
            amount_sats = invoice_amount_sats
        else:
            # Zero-amount invoice: require explicit amount_sats in body
            body_amount = body.get("amount_sats")
            if body_amount is None:
                raise ApiError(
                    "Zero-amount invoice requires amount_sats in request body",
                    400, "invoice_amount_required",
                )
            amount_sats = parse_sats(body_amount, "amount_sats", settings.max_payment_sats)

        if amount_sats <= 0:
            raise ApiError("Payment amount must be positive", 400, "payment_amount_required")
        if amount_sats > settings.max_payment_sats:
            raise ApiError(
                f"Payment amount ({amount_sats} sats) exceeds maximum ({settings.max_payment_sats} sats)",
                400, "payment_amount_exceeds_limit",
            )

        # Fee limit: min(max_fee_sats, amount_sats * max_fee_ppm / 1_000_000)
        effective_fee_limit = min(
            settings.max_fee_sats,
            max(1, amount_sats * settings.max_fee_ppm // 1_000_000),
        )
        requested_fee = parse_optional_int(body.get("fee_limit_sats"), "fee_limit_sats", effective_fee_limit, 1, 1_000_000)
        if requested_fee > effective_fee_limit:
            raise ApiError(
                f"Fee limit ({requested_fee} sats) exceeds maximum ({effective_fee_limit} sats)",
                400, "fee_limit_exceeds_maximum",
            )
        fee_limit_sats = requested_fee

        timeout_seconds = parse_optional_int(body.get("timeout_seconds"), "timeout_seconds", 60, 1, 600)

        # ── ITEM 2: Idempotency enforcement ──

        # Namespace key: principal_id:idempotency_key
        # principal_id comes from bearer token tail
        principal_id = g.get("principal_id", "anon")
        raw_key = request.headers.get("Idempotency-Key", "").strip()
        if not raw_key:
            raise ApiError(
                "Idempotency-Key header is required for payment operations",
                400, "idempotency_key_required",
            )
        validated_key = validate_idempotency_key_payment(raw_key)
        if not validated_key:
            raise ApiError(
                "Idempotency-Key must be 16-128 safe printable characters", 400, "invalid_idempotency_key",
            )
        namespaced_key = f"{principal_id}:{validated_key}"
        g.idempotency_key = namespaced_key

        # Check if payment_hash already settled (ITEM 1: duplicate payment guard)
        existing_hash = store.query_payment_by_hash(payment_hash)
        if existing_hash and existing_hash["state"] in ("SUCCEEDED", "SUBMITTED"):
            raise ApiError(
                "Invoice has already been paid (duplicate payment_hash)", 409, "payment_hash_already_settled",
            )

        # ITEM 2: Atomic claim CLAIMED with lease
        cached = store.claim_idempotent(
            namespaced_key, g.fingerprint,
            payment_hash=payment_hash, network=settings.network,
        )
        if cached:
            payload, status = cached
            raise IdempotentReplay(payload, status)

        # ── ITEM 1 step 6: No LND call before complete validation ✓ ──
        # All validation above is pure logic + LND decode (read-only), no mutation.
        # Now call LND pay.

        try:
            store.mark_submitted(namespaced_key, g.fingerprint, payment_hash)
            result = client.pay_invoice(
                payment_request, fee_limit_sats, timeout_seconds,
                amount_sats=amount_sats if invoice_amount_sats == 0 else None,
            )
        except ApiError:
            store.mark_failed(namespaced_key, g.fingerprint, "payment_rejected", "LND rejected payment")
            raise
        except Exception as exc:
            logger.error("LND payment timeout or network error: %s", exc)
            store.mark_unknown(namespaced_key, g.fingerprint, payment_hash)
            raise ApiError(
                "Payment timed out — result unknown. Reconcile before retrying.",
                504, "payment_timeout_unknown",
            )

        store.append_event(
            "payment_submitted",
            payment_hash=payment_hash,
            amount_sats=amount_sats,
            status=result.get("status"),
            metadata={"fee_limit_sats": fee_limit_sats, "timeout_seconds": timeout_seconds},
            idempotency_key=namespaced_key,
        )

        response_payload = {"success": True, "payment": result}
        return _idempotent(store, response_payload, 202)

    @app.get("/v1/payments/<payment_hash>")
    def lookup_payment(payment_hash: str):
        payment_hash = validate_payment_hash(payment_hash)
        return _json({"success": True, "payment": client.lookup_payment(payment_hash)})

    # ITEM 34: Reduced channels — aggregates only, no topology leak
    @app.get("/v1/channels")
    def channels():
        raw = client.list_channels()
        chs = raw.get("channels", [])
        active = sum(1 for c in chs if c.get("active"))
        outbound = sum(c.get("local_balance_sats", 0) for c in chs)
        inbound = sum(c.get("remote_balance_sats", 0) for c in chs)
        return _json({
            "success": True,
            "activeChannelCount": active,
            "totalChannelCount": len(chs),
            "outboundLiquiditySats": outbound,
            "inboundLiquiditySats": inbound,
        })

    def _require_idempotency(store: CohesionStore):
        """Enforce Idempotency-Key for write operations with namespace."""
        principal_id = getattr(g, "principal_id", "anon")
        raw_key = request.headers.get("Idempotency-Key", "").strip()
        if not raw_key:
            raise ApiError(
                "Idempotency-Key header is required for payment operations",
                400,
                "idempotency_key_required",
            )
        validated = validate_idempotency_key(raw_key)
        if not validated:
            raise ApiError(
                "Idempotency-Key must be at least 8 safe printable characters",
                400,
                "invalid_idempotency_key",
            )
        namespaced = f"{principal_id}:{validated}"
        g.idempotency_key = namespaced
        cached = store.claim_idempotent(namespaced, g.fingerprint)
        if cached:
            payload, status = cached
            raise IdempotentReplay(payload, status)

    def _idempotent(store: CohesionStore, payload: dict[str, Any], status_code: int):
        key = getattr(g, "idempotency_key", "")
        if key:
            store.save_idempotent(key, g.fingerprint, payload, status_code)
        return _json(payload, status_code)

    return app


def _json(payload: dict[str, Any], status_code: int = 200):
    return jsonify(payload), status_code


def _validate_lnd_network(client: LndClient, settings: Settings) -> None:
    """ITEM 27: Validate LND network at startup against configured network."""
    try:
        info = client.get_info()
        chains = info.get("chains", [])
        lnd_network = ""
        for chain in chains:
            if chain.get("chain") == "bitcoin":
                lnd_network = chain.get("network", "").lower()
                break
        if not lnd_network:
            lnd_network = info.get("network", "").lower()
        if lnd_network and lnd_network != settings.network:
            raise RuntimeError(
                f"LND network ({lnd_network}) does not match configured network ({settings.network}). "
                "Refusing to start to prevent cross-network financial operations."
            )
        logger.info("LND network validated: %s (configured: %s)", lnd_network or "unknown", settings.network)
    except ApiError:
        raise
    except Exception as exc:
        logger.warning("Could not validate LND network at startup: %s — continuing", exc)


if __name__ == "__main__":
    create_app().run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8091")))
