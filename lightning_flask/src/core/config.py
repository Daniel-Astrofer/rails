from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_token: str
    read_token: str
    write_token: str
    admin_token: str
    network: str
    lnd_rest_url: str
    lnd_macaroon_hex: str = ""
    lnd_macaroon_path: str = ""
    lnd_tls_cert_path: str = ""
    lnd_timeout_seconds: float = 8.0
    sqlite_path: str = "lightning_backend.sqlite3"
    max_body_bytes: int = 64 * 1024
    rate_limit_per_minute: int = 120
    rate_limit_backend: str = "memory"
    redis_url: str = ""
    status_cache_seconds: float = 2.0
    max_invoice_sats: int = 50_000_000
    max_payment_sats: int = 50_000_000
    max_fee_sats: int = 5_000
    max_fee_ppm: int = 500
    max_daily_payment_sats: int = 100_000_000
    max_in_flight_sats: int = 50_000_000
    default_invoice_expiry_seconds: int = 3600
    auth_disabled: bool = False
    production: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        read_token = os.getenv("LIGHTNING_READ_TOKEN", "")
        write_token = os.getenv("LIGHTNING_WRITE_TOKEN", "")
        api_token = os.getenv("KEROSENE_API_TOKEN", "")
        auth_disabled = os.getenv("LIGHTNING_AUTH_DISABLED", "").strip().lower() in {"1", "true", "yes", "on"}
        production = os.getenv("LIGHTNING_PRODUCTION", "").strip().lower() in {"1", "true", "yes", "on"}
        if api_token and not read_token and not write_token:
            read_token = api_token
            write_token = api_token
        return cls(
            api_token=api_token,
            read_token=read_token,
            write_token=write_token,
            admin_token=os.getenv("LIGHTNING_ADMIN_TOKEN", ""),
            network=os.getenv("LIGHTNING_NETWORK", "mainnet").lower(),
            lnd_rest_url=os.getenv("LIGHTNING_LND_REST_URL", "https://127.0.0.1:8080"),
            lnd_macaroon_hex=os.getenv("LIGHTNING_LND_MACAROON_HEX", ""),
            lnd_macaroon_path=os.getenv("LIGHTNING_LND_MACAROON_PATH", ""),
            lnd_tls_cert_path=os.getenv("LIGHTNING_LND_TLS_CERT_PATH", ""),
            lnd_timeout_seconds=float(os.getenv("LIGHTNING_LND_TIMEOUT_SECONDS", "8")),
            sqlite_path=os.getenv("LIGHTNING_BACKEND_SQLITE", "lightning_backend.sqlite3"),
            max_body_bytes=int(os.getenv("LIGHTNING_BACKEND_MAX_BODY_BYTES", str(64 * 1024))),
            rate_limit_per_minute=int(os.getenv("LIGHTNING_BACKEND_RATE_LIMIT_PER_MINUTE", "120")),
            rate_limit_backend=os.getenv("LIGHTNING_RATE_LIMIT_BACKEND", "memory").lower(),
            redis_url=os.getenv("LIGHTNING_REDIS_URL", ""),
            status_cache_seconds=float(os.getenv("LIGHTNING_BACKEND_STATUS_CACHE_SECONDS", "2")),
            max_invoice_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_INVOICE_SATS", "50000000")),
            max_payment_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_PAYMENT_SATS", "50000000")),
            max_fee_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_FEE_SATS", "5000")),
            max_fee_ppm=int(os.getenv("LIGHTNING_BACKEND_MAX_FEE_PPM", "500")),
            max_daily_payment_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_DAILY_PAYMENT_SATS", "100000000")),
            max_in_flight_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_IN_FLIGHT_SATS", "50000000")),
            default_invoice_expiry_seconds=int(os.getenv("LIGHTNING_DEFAULT_INVOICE_EXPIRY_SECONDS", "3600")),
            auth_disabled=auth_disabled,
            production=production,
        )

    def validate(self) -> None:
        # ITEM 25: prohibit disabled auth in production
        if self.auth_disabled and self.production:
            raise ValueError("LIGHTNING_AUTH_DISABLED cannot be true in production")
        # ITEM 25: prohibit disabled auth on non-loopback bind
        host = os.getenv("HOST", "127.0.0.1").strip()
        if self.auth_disabled and host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Auth cannot be disabled when binding to non-loopback address")

        # ITEM 24: validate token entropy (min 32 bytes = 64 hex or ~43 base64)
        def _valid_token(tok: str) -> bool:
            if not tok or len(tok) < 43:
                return False
            import re
            if re.fullmatch(r'[0-9a-fA-F]{64,}', tok):
                # hex: 32+ bytes
                return True
            if re.fullmatch(r'[A-Za-z0-9+/=_-]{43,}', tok):
                # base64url: ~32+ bytes
                return True
            return False

        for name, tok in [("LIGHTNING_READ_TOKEN", self.read_token),
                          ("LIGHTNING_WRITE_TOKEN", self.write_token),
                          ("LIGHTNING_ADMIN_TOKEN", self.admin_token)]:
            if tok and not _valid_token(tok):
                raise ValueError(f"{name} must have at least 32 bytes of entropy (64 hex or ~43 base64 chars)")
        if not self.read_token and not self.write_token:
            if not _valid_token(self.api_token):
                raise ValueError("KEROSENE_API_TOKEN must have at least 32 bytes of entropy (64 hex or ~43 base64 chars)")

        if self.network not in {"mainnet", "testnet", "regtest", "signet"}:
            raise ValueError("LIGHTNING_NETWORK must be mainnet, testnet, regtest, or signet")
        if not self.lnd_rest_url.startswith(("http://", "https://")):
            raise ValueError("LIGHTNING_LND_REST_URL must use http or https")
        if not self.lnd_macaroon_hex and not self.lnd_macaroon_path:
            raise ValueError("LIGHTNING_LND_MACAROON_HEX or LIGHTNING_LND_MACAROON_PATH is required")
        if self.max_invoice_sats < 1 or self.max_payment_sats < 1:
            raise ValueError("Lightning amount limits must be positive")
        if self.max_fee_sats < 1:
            raise ValueError("LIGHTNING_BACKEND_MAX_FEE_SATS must be positive")
        if self.max_fee_ppm < 1:
            raise ValueError("LIGHTNING_BACKEND_MAX_FEE_PPM must be positive")
        if self.rate_limit_backend not in {"memory", "redis"}:
            raise ValueError("LIGHTNING_RATE_LIMIT_BACKEND must be 'memory' or 'redis'")
        if self.rate_limit_backend == "redis" and not self.redis_url:
            raise ValueError("LIGHTNING_REDIS_URL is required when LIGHTNING_RATE_LIMIT_BACKEND=redis")
