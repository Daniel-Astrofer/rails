from __future__ import annotations

import os
from dataclasses import dataclass
from typing import FrozenSet


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, minimum: int | None = None) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        parsed = default
    else:
        parsed = int(value)
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return parsed


def _float_env(name: str, default: float, minimum: float | None = None) -> float:
    value = os.getenv(name)
    if value is None or value == "":
        parsed = default
    else:
        parsed = float(value)
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return parsed


def _api_keys() -> FrozenSet[str]:
    raw = os.getenv("BITCOIN_BACKEND_API_KEYS") or os.getenv("KEROSENE_BACKEND_API_KEYS") or ""
    keys = frozenset(item.strip() for item in raw.split(",") if item.strip())
    weak = [key for key in keys if _token_entropy(key) < 32]
    if weak:
        raise ValueError("BITCOIN_BACKEND_API_KEYS entries must have at least 32 bytes of entropy (64 hex or ~43 base64 chars)")
    return keys


def _read_api_keys() -> FrozenSet[str]:
    raw = os.getenv("BITCOIN_BACKEND_READ_API_KEYS") or ""
    keys = frozenset(item.strip() for item in raw.split(",") if item.strip())
    weak = [key for key in keys if _token_entropy(key) < 32]
    if weak:
        raise ValueError("BITCOIN_BACKEND_READ_API_KEYS entries must have at least 32 bytes of entropy (64 hex or ~43 base64 chars)")
    return keys


def _write_api_keys() -> FrozenSet[str]:
    raw = os.getenv("BITCOIN_BACKEND_WRITE_API_KEYS") or ""
    keys = frozenset(item.strip() for item in raw.split(",") if item.strip())
    weak = [key for key in keys if _token_entropy(key) < 32]
    if weak:
        raise ValueError("BITCOIN_BACKEND_WRITE_API_KEYS entries must have at least 32 bytes of entropy (64 hex or ~43 base64 chars)")
    return keys


def _token_entropy(token: str) -> int:
    """ITEM 24: Estimate entropy in bytes for a token.
    Accepts hex (64+ chars) or base64url (~43+ chars)."""
    import re
    if re.fullmatch(r'[0-9a-fA-F]{64,}', token):
        return len(token) // 2
    if re.fullmatch(r'[A-Za-z0-9+/=_-]{43,}', token):
        raw = len(token.rstrip("="))
        return raw * 6 // 8
    return 0


@dataclass(frozen=True)
class AppConfig:
    rpc_url: str
    rpc_user: str
    rpc_password: str
    default_wallet: str
    chain: str
    api_keys: FrozenSet[str]
    read_api_keys: FrozenSet[str]
    write_api_keys: FrozenSet[str]
    admin_token: str
    auth_disabled: bool
    allow_wallet_create: bool
    allow_broadcast: bool
    connect_timeout_seconds: float
    read_timeout_seconds: float
    rpc_pool_size: int
    max_content_length: int
    max_outputs_per_tx: int
    max_send_sats: int
    default_min_confirmations: int
    idempotency_ttl_seconds: int
    state_db_path: str
    rate_limit_per_minute: int
    rate_limit_backend: str
    redis_url: str

    @classmethod
    def from_env(cls) -> "AppConfig":
        auth_disabled = _bool_env("BITCOIN_BACKEND_AUTH_DISABLED", False)
        keys = _api_keys()
        read_keys = _read_api_keys()
        write_keys = _write_api_keys()
        admin_token = os.getenv("BITCOIN_BACKEND_ADMIN_TOKEN", "")
        # Backward compat: if scoped keys are empty, fall back to api_keys for both
        if not read_keys and not write_keys:
            if keys:
                read_keys = keys
                write_keys = keys
            elif not auth_disabled:
                raise ValueError(
                    "Set BITCOIN_BACKEND_API_KEYS, BITCOIN_BACKEND_READ_API_KEYS / "
                    "BITCOIN_BACKEND_WRITE_API_KEYS, or explicitly set "
                    "BITCOIN_BACKEND_AUTH_DISABLED=true for local development."
                )

        return cls(
            rpc_url=os.getenv("BITCOIN_RPC_URL", "http://bitcoin-core:8332").rstrip("/"),
            rpc_user=os.getenv("BITCOIN_RPC_USER", ""),
            rpc_password=os.getenv("BITCOIN_RPC_PASSWORD", ""),
            default_wallet=os.getenv("BITCOIN_RPC_WALLET", "kerosene"),
            chain=os.getenv("BITCOIN_CHAIN", "mainnet"),
            api_keys=keys,
            read_api_keys=read_keys,
            write_api_keys=write_keys,
            admin_token=admin_token,
            auth_disabled=auth_disabled,
            allow_wallet_create=_bool_env("BITCOIN_BACKEND_ALLOW_WALLET_CREATE", False),
            allow_broadcast=_bool_env("BITCOIN_BACKEND_ALLOW_BROADCAST", False),
            connect_timeout_seconds=_float_env("BITCOIN_BACKEND_CONNECT_TIMEOUT_SECONDS", 2.0, 0.1),
            read_timeout_seconds=_float_env("BITCOIN_BACKEND_READ_TIMEOUT_SECONDS", 20.0, 0.1),
            rpc_pool_size=_int_env("BITCOIN_BACKEND_RPC_POOL_SIZE", 16, 1),
            max_content_length=_int_env("BITCOIN_BACKEND_MAX_CONTENT_LENGTH", 64 * 1024, 1024),
            max_outputs_per_tx=_int_env("BITCOIN_BACKEND_MAX_OUTPUTS_PER_TX", 64, 1),
            max_send_sats=_int_env("BITCOIN_BACKEND_MAX_SEND_SATS", 10_000_000, 1),
            default_min_confirmations=_int_env("BITCOIN_BACKEND_MIN_CONFIRMATIONS", 1, 0),
            idempotency_ttl_seconds=_int_env("BITCOIN_BACKEND_IDEMPOTENCY_TTL_SECONDS", 24 * 60 * 60, 60),
            state_db_path=os.getenv("BITCOIN_BACKEND_DB_PATH", "/tmp/kerosene-bitcoin-core-backend.sqlite3"),
            rate_limit_per_minute=_int_env("BITCOIN_BACKEND_RATE_LIMIT_PER_MINUTE", 120, 1),
            rate_limit_backend=os.getenv("BITCOIN_BACKEND_RATE_LIMIT_BACKEND", "memory").lower(),
            redis_url=os.getenv("BITCOIN_BACKEND_REDIS_URL", ""),
        )

    @property
    def rpc_timeout(self) -> tuple[float, float]:
        return (self.connect_timeout_seconds, self.read_timeout_seconds)
