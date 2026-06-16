from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections import defaultdict, deque
from typing import Any

from flask import Request


INVOICE_RE = re.compile(r"^(ln(bc|tb|bcrt)[0-9a-z]{20,4096})$", re.IGNORECASE)
HEX_32_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ApiError(Exception):
    def __init__(self, message: str, status_code: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class RateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit = max(1, int(limit_per_minute))
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        bucket = self._hits[key]
        cutoff = now - 60
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            raise ApiError("Too many requests", 429, "rate_limited")
        bucket.append(now)


def require_bearer_token(request: Request, expected_token: str) -> None:
    header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        raise ApiError("Missing bearer token", 401, "unauthorized")
    supplied = header[len(prefix) :].strip()
    if not expected_token or not hmac.compare_digest(supplied, expected_token):
        raise ApiError("Invalid bearer token", 401, "unauthorized")


def request_fingerprint(request: Request) -> str:
    body = request.get_data(cache=True) or b""
    return hashlib.sha256(request.method.encode() + b"\n" + request.path.encode() + b"\n" + body).hexdigest()


def require_json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ApiError("JSON body must be an object", 400, "invalid_json")
    return value


def parse_sats(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise ApiError(f"{field} must be an integer number of sats", 400, "invalid_amount")
    try:
        sats = int(str(value))
    except (TypeError, ValueError):
        raise ApiError(f"{field} must be an integer number of sats", 400, "invalid_amount") from None
    if sats <= 0:
        raise ApiError(f"{field} must be positive", 400, "invalid_amount")
    if sats > maximum:
        raise ApiError(f"{field} exceeds configured limit", 400, "amount_too_large")
    return sats


def parse_optional_int(value: Any, field: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ApiError(f"{field} must be an integer", 400, "invalid_integer")
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        raise ApiError(f"{field} must be an integer", 400, "invalid_integer") from None
    if parsed < minimum or parsed > maximum:
        raise ApiError(f"{field} is outside allowed range", 400, "invalid_integer")
    return parsed


def validate_memo(value: Any) -> str:
    memo = str(value or "")
    if len(memo) > 256:
        raise ApiError("memo is too long", 400, "invalid_memo")
    return memo


def validate_bolt11(value: Any) -> str:
    invoice = str(value or "").strip()
    if not INVOICE_RE.fullmatch(invoice):
        raise ApiError("payment_request must be a BOLT11 Lightning invoice", 400, "invalid_invoice")
    return invoice


def validate_payment_hash(value: Any) -> str:
    payment_hash = str(value or "").strip()
    if not HEX_32_RE.fullmatch(payment_hash):
        raise ApiError("payment_hash must be 32 bytes encoded as hex", 400, "invalid_payment_hash")
    return payment_hash.lower()
