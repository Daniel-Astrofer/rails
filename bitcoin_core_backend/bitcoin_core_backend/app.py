from __future__ import annotations

import hmac
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Callable

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import BadRequest

from .config import AppConfig
from .errors import ApiError, RpcError, rpc_error_to_api_error
from .rpc import BitcoinRPCClient
from .services import BitcoinBackendService, fingerprint_for_request
from .store import CohesionStore
from .validation import validate_idempotency_key, validate_wallet_name


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


def create_app(config: AppConfig | None = None) -> Flask:
    cfg = config or AppConfig.from_env()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_content_length

    rpc = BitcoinRPCClient(cfg)
    store = CohesionStore(cfg.state_db_path, cfg.idempotency_ttl_seconds)
    service = BitcoinBackendService(cfg, rpc, store)
    limiter = FixedWindowLimiter(cfg.rate_limit_per_minute)

    @app.before_request
    def before_request() -> Response | None:
        g.request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        if request.path == "/healthz":
            return None

        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.content_type or ""
            if not content_type.startswith("application/json"):
                raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Use application/json for requests with a body.")

        principal = _authenticate(cfg)
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
        return jsonify({"success": True, "status": "ok", "requestId": g.get("request_id")})

    @app.get("/v1/node/status")
    def node_status() -> Response:
        return jsonify(_ok(service.node_status()))

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

    @app.get("/v1/cohesion/idempotency/<key>")
    def idempotency_probe(key: str) -> Response:
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

    idempotency_key = validate_idempotency_key(request.headers.get("Idempotency-Key"))
    if require_idempotency and not idempotency_key:
        raise ApiError(428, "IDEMPOTENCY_REQUIRED", "Idempotency-Key header is required.")

    request_hash = fingerprint_for_request(request.method, request.path, body)
    scope = f"{request.method}:{request.path}"
    if idempotency_key:
        replay = store.get_replay(idempotency_key, scope, request_hash)
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
    if idempotency_key and 200 <= status_code < 300:
        store.store_response(idempotency_key, scope, request_hash, status_code, response_body)
    return jsonify(response_body), status_code


def _authenticate(config: AppConfig) -> str | None:
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
