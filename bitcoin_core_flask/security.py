from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections import defaultdict, deque
from decimal import Decimal, InvalidOperation
from typing import Any

from flask import Request


WALLET_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ADDRESS_RE = re.compile(r"^[A-Za-z0-9:]{14,90}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class ApiError(Exception):
    def __init__(self, message: str, status_code: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class RateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit = max(1, limit_per_minute)
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


def validate_wallet_name(wallet: str) -> str:
    value = (wallet or "").strip()
    if not WALLET_RE.fullmatch(value):
        raise ApiError("wallet must contain only letters, numbers, dots, underscores, or hyphens", 400, "invalid_wallet")
    if value in {".", ".."}:
        raise ApiError("wallet name is not allowed", 400, "invalid_wallet")
    return value


def require_json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ApiError("JSON body must be an object", 400, "invalid_json")
    return value


def parse_btc_amount(value: Any, field: str = "amount_btc") -> str:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ApiError(f"{field} must be a decimal BTC amount", 400, "invalid_amount") from None
    if amount <= 0:
        raise ApiError(f"{field} must be positive", 400, "invalid_amount")
    if amount.as_tuple().exponent < -8:
        raise ApiError(f"{field} may not exceed 8 decimal places", 400, "invalid_amount")
    return format(amount, "f")


def validate_address(value: Any) -> str:
    address = str(value or "").strip()
    if not ADDRESS_RE.fullmatch(address):
        raise ApiError("destination address is invalid", 400, "invalid_address")
    return address


def validate_tx_hex(value: Any) -> str:
    tx_hex = str(value or "").strip()
    if len(tx_hex) < 20 or len(tx_hex) > 400_000 or len(tx_hex) % 2 != 0 or not HEX_RE.fullmatch(tx_hex):
        raise ApiError("raw_tx_hex is invalid", 400, "invalid_transaction_hex")
    return tx_hex
