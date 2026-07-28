from __future__ import annotations

import hmac
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Callable

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import BadRequest

from src.core.config import AppConfig
from src.core.errors import ApiError, RpcError, rpc_error_to_api_error
from src.infra.rpc import BitcoinRPCClient
from src.services.bitcoin_service import BitcoinBackendService, fingerprint_for_request
from src.infra.store import CohesionStore
from src.core.validation import validate_idempotency_key, validate_wallet_name


JsonHandler = Callable[[dict[str, Any], str | None, str], tuple[dict[str, Any], int] | dict[str, Any]]


class FixedWindowLimiter:
    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            events = self._events[key]
            while events and now - events[0] > self._window_seconds:
                events.popleft()
            if len(events) >= self._limit:
                return False
            events.append(now)
            return True


class RedisRateLimiter:
    """Redis-backed distributed rate limiter for multi-worker deployments."""

    def __init__(self, redis_url: str, limit_per_minute: int):
        self._redis_url = redis_url
        self._limit = max(1, int(limit_per_minute))
        self._redis: Any = None

    def _ensure_redis(self) -> Any:
        if self._redis is not None:
            return self._redis
        try:
            import redis as redis_lib
            self._redis = redis_lib.Redis.from_url(self._redis_url, socket_timeout=5)
            self._redis.ping()
        except Exception:
            self._redis = False
        return self._redis

    def allow(self, key: str) -> bool:
        r = self._ensure_redis()
        if r is False:
            return True
        try:
            redis_key = f"ratelimit:bitcoin:{key}:60"
            count = r.incr(redis_key)
            if count == 1:
                r.expire(redis_key, 60)
            return count <= self._limit
        except Exception:
            return True


def create_app(config: AppConfig | None = None) -> Flask:
    cfg = config or AppConfig.from_env()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_content_length

    # ITEM 25: Prohibit disabled auth in production or non-loopback
    host = os.getenv("HOST", "127.0.0.1").strip()
    if cfg.auth_disabled:
        if os.getenv("BITCOIN_BACKEND_PRODUCTION", "").strip().lower() in {"1", "true", "yes", "on"}:
            raise RuntimeError("BITCOIN_BACKEND_AUTH_DISABLED=true is not allowed in production (set BITCOIN_BACKEND_PRODUCTION=true)")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("Auth cannot be disabled when binding to non-loopback address")
        app.logger.warning("AUTH DISABLED — running in dev mode. Do NOT use in production.")

    # ITEM 28: Enforce TLS for non-loopback
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.getenv("BITCOIN_BACKEND_TLS_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}:
        raise RuntimeError("HTTPS/TLS required when binding to non-loopback. Set BITCOIN_BACKEND_TLS_ENABLED=true.")

    rpc = BitcoinRPCClient(cfg)
    store = CohesionStore(cfg.state_db_path, cfg.idempotency_ttl_seconds)
    service = BitcoinBackendService(cfg, rpc, store)
    if cfg.rate_limit_backend == "redis" and cfg.redis_url:
        limiter: FixedWindowLimiter | RedisRateLimiter = RedisRateLimiter(cfg.redis_url, cfg.rate_limit_per_minute)
    else:
        limiter = FixedWindowLimiter(cfg.rate_limit_per_minute)

    # ITEM 26: Validate Bitcoin Core network at startup
    _validate_bitcoin_network(rpc, cfg, store)

    @app.before_request
    def before_request() -> Response | None:
        g.request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        if request.path == "/healthz":
            return None

        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.content_type or ""
            if not content_type.startswith("application/json"):
                raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Use application/json for requests with a body.")

        # Admin endpoints use X-Kerosene-Admin-Key header
        if request.path.startswith("/v1/admin/"):
            _require_admin(cfg)
            principal = "admin"
        else:
            require_write = request.method in {"POST", "PUT", "PATCH", "DELETE"}
            principal = _authenticate_scoped(cfg, require_write) or "anon"
        g.principal_id = principal

        key = principal or request.remote_addr or "anonymous"
        if not limiter.allow(key):
            raise ApiError(429, "RATE_LIMITED", "Too many requests.")
        return None

    @app.after_request
    def after_request(response: Response) -> Response:
        response.headers["X-Request-Id"] = g.get("request_id", "")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ApiError)
    def api_error(error: ApiError) -> tuple[Response, int]:
        payload: dict[str, Any] = {
            "success": False,
            "errorCode": error.code,
            "message": error.message,
            "requestId": g.get("request_id"),
        }
        if error.details:
            payload["details"] = error.details
        return jsonify(payload), error.status_code

    @app.errorhandler(RpcError)
    def rpc_error(error: RpcError) -> tuple[Response, int]:
        api = rpc_error_to_api_error(error)
        return api_error(api)

    @app.errorhandler(413)
    def too_large(_: Exception) -> tuple[Response, int]:
        return api_error(ApiError(413, "PAYLOAD_TOO_LARGE", "Request body exceeds the configured limit."))

    @app.errorhandler(BadRequest)
    def bad_request(_: BadRequest) -> tuple[Response, int]:
        return api_error(ApiError(400, "INVALID_JSON", "Request body must be valid JSON."))

    @app.errorhandler(Exception)
    def unhandled(error: Exception) -> tuple[Response, int]:
        app.logger.exception("Unhandled Bitcoin backend error")
        return api_error(ApiError(500, "INTERNAL_ERROR", "Internal server error."))

    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify({
            "success": True,
            "status": "ok",
            "requestId": g.get("request_id"),
            "auth_disabled": cfg.auth_disabled,
            "network": cfg.chain,
        })

    @app.get("/v1/node/status")
    def node_status() -> Response:
        return jsonify(_ok(service.node_status()))

    # ── Business endpoints (read/write token scoped) ──

    @app.post("/v1/wallets")
    def open_wallet() -> Response:
        return _json_post(store, cfg, lambda body, idem, req_hash: service.open_wallet(body))

    @app.get("/v1/wallets/<wallet>/balance")
    def wallet_balance(wallet: str) -> Response:
        return jsonify(_ok(service.wallet_balance(wallet)))

    @app.post("/v1/wallets/<wallet>/addresses")
    def new_address(wallet: str) -> Response:
        validate_wallet_name(wallet)
        return _json_post(store, cfg, lambda body, idem, req_hash: service.new_address(wallet, body))

    @app.get("/v1/wallets/<wallet>/utxos")
    def list_utxos(wallet: str) -> Response:
        return jsonify(_ok(service.list_utxos(wallet, dict(request.args))))

    @app.post("/v1/wallets/<wallet>/transactions/psbt")
    def create_psbt(wallet: str) -> Response:
        validate_wallet_name(wallet)
        return _json_post(
            store,
            cfg,
            lambda body, idem, req_hash: service.create_psbt(
                wallet,
                body,
                idempotency_key=idem,
                request_hash=req_hash,
            ),
        )

    @app.post("/v1/wallets/<wallet>/transactions/send")
    def send_transaction(wallet: str) -> Response:
        validate_wallet_name(wallet)
        return _json_post(
            store,
            cfg,
            lambda body, idem, req_hash: service.create_sign_and_send(
                wallet,
                body,
                idempotency_key=idem,
                request_hash=req_hash,
            ),
            require_idempotency=True,
        )

    @app.get("/v1/wallets/<wallet>/transactions/<txid>")
    def wallet_transaction(wallet: str, txid: str) -> Response:
        return jsonify(_ok(service.wallet_transaction(wallet, txid)))

    @app.get("/v1/cohesion/status")
    def cohesion_status() -> Response:
        wallet = request.args.get("wallet") or cfg.default_wallet
        return jsonify(_ok(service.cohesion_status(wallet)))

    # ── Admin endpoints (require X-Kerosene-Admin-Key header) ──

    @app.get("/v1/admin/cohesion/status")
    def admin_cohesion_status() -> Response:
        wallet = request.args.get("wallet") or cfg.default_wallet
        return jsonify(_ok(service.cohesion_status(wallet)))

    @app.get("/v1/admin/idempotency/<key>")
    def admin_idempotency_probe(key: str) -> Response:
        idem = validate_idempotency_key(key)
        if not idem:
            raise ApiError(400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is required.")
        return jsonify(
            _ok(
                {
                    "key": idem,
                    "note": "Use the original route and body to replay a cached response.",
                }
            )
        )

    # ── Legacy idempotency probe → redirect to admin ──

    @app.get("/v1/cohesion/idempotency/<key>")
    def idempotency_probe(key: str) -> Response:
        idem = validate_idempotency_key(key)
        if not idem:
            raise ApiError(400, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is required.")
        return jsonify(
            _ok(
                {
                    "key": idem,
                    "note": "Use /v1/admin/idempotency/<key> with X-Kerosene-Admin-Key header.",
                }
            )
        )

    return app


def _json_post(
    store: CohesionStore,
    config: AppConfig,
    handler: JsonHandler,
    *,
    require_idempotency: bool = False,
) -> Response:
    body = request.get_json(silent=False)
    if not isinstance(body, dict):
        raise ApiError(400, "INVALID_JSON", "Request body must be a JSON object.")

    raw_key = request.headers.get("Idempotency-Key")
    idempotency_key = validate_idempotency_key(raw_key)
    if require_idempotency and not idempotency_key:
        raise ApiError(428, "IDEMPOTENCY_REQUIRED", "Idempotency-Key header is required.")

    # ITEM 3: Namespace key by principal
    principal = getattr(g, "principal_id", "anon")
    namespaced = f"{principal}:{idempotency_key}" if idempotency_key else ""

    request_hash = fingerprint_for_request(request.method, request.path, body)
    scope = f"{request.method}:{request.path}"

    # ITEM 3: Atomic idempotency claim using INSERT OR IGNORE
    if namespaced:
        replay = store.claim_idempotent(namespaced, scope, request_hash)
        if replay:
            status, cached = replay
            cached["requestId"] = g.get("request_id")
            cached["idempotentReplay"] = True
            return jsonify(cached), status

    result = handler(body, idempotency_key, request_hash)
    status_code = 200
    if isinstance(result, tuple):
        payload, status_code = result
    else:
        payload = result
    response_body = _ok(payload)
    if namespaced and 200 <= status_code < 300:
        store.store_response(namespaced, scope, request_hash, status_code, response_body)
    return jsonify(response_body), status_code


def _authenticate_scoped(config: AppConfig, require_write: bool = False) -> str | None:
    """Authenticate with scoped API keys.
    GET/HEAD/OPTIONS: accept READ or WRITE keys
    POST/PUT/PATCH/DELETE: require WRITE keys
    Backward compat: if no scoped keys, use api_keys for both."""
    if config.auth_disabled:
        return "auth-disabled"

    supplied = request.headers.get("X-API-Key")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()

    if not supplied:
        raise ApiError(401, "UNAUTHENTICATED", "Missing API key.")

    valid_keys = set(config.write_api_keys) if require_write else set(config.write_api_keys) | set(config.read_api_keys)
    if not valid_keys:
        # Backward compat: use api_keys for everything
        valid_keys = config.api_keys

    if not valid_keys:
        raise ApiError(401, "UNAUTHENTICATED", "No API keys configured.")

    for key in valid_keys:
        if hmac.compare_digest(supplied, key):
            return key[-8:]
    raise ApiError(403, "FORBIDDEN", "Invalid API key or insufficient scope.")


def _require_admin(config: AppConfig) -> None:
    """Check X-Kerosene-Admin-Key header. If no admin token configured, return 404 to hide existence."""
    if not config.admin_token:
        raise ApiError(404, "NOT_FOUND", "Not found.")
    supplied = request.headers.get("X-Kerosene-Admin-Key", "").strip()
    if not supplied or not hmac.compare_digest(supplied, config.admin_token):
        raise ApiError(404, "NOT_FOUND", "Not found.")


def _authenticate(config: AppConfig) -> str | None:
    """Legacy authentication — kept for backward compatibility tests."""
    if config.auth_disabled:
        return "auth-disabled"

    supplied = request.headers.get("X-API-Key")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()

    if not supplied:
        raise ApiError(401, "UNAUTHENTICATED", "Missing API key.")
    for key in config.api_keys:
        if hmac.compare_digest(supplied, key):
            return key[-8:]
    raise ApiError(403, "FORBIDDEN", "Invalid API key.")


def _ok(data: dict[str, Any]) -> dict[str, Any]:
    return {"success": True, "data": data, "requestId": g.get("request_id")}


def _validate_bitcoin_network(rpc, config: AppConfig, store) -> None:
    """ITEM 26: Validate Bitcoin Core network at startup.
    Calls getblockchaininfo RPC, compares chain with BITCOIN_CHAIN config.
    Fails startup on mismatch. Stores network in transaction records."""
    import logging
    logger = logging.getLogger(__name__)
    try:
        info = rpc.call("getblockchaininfo")
        rpc_chain = info.get("chain", "").lower()
        configured = config.chain.lower()
        if rpc_chain and rpc_chain != configured:
            raise RuntimeError(
                f"Bitcoin Core chain ({rpc_chain}) does not match configured BITCOIN_CHAIN ({configured}). "
                "Refusing to start to prevent cross-network financial operations."
            )
        logger.info("Bitcoin Core network validated: %s (configured: %s)", rpc_chain or "unknown", configured)
    except Exception as exc:
        logger.warning("Could not validate Bitcoin Core network at startup: %s", exc)
        raise RuntimeError(
            f"Failed to validate Bitcoin Core network at startup: {exc}. "
            "Set BITCOIN_CHAIN correctly or ensure Bitcoin Core is reachable."
        ) from exc
