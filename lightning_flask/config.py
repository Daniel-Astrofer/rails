from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_token: str
    lnd_rest_url: str
    lnd_macaroon_hex: str = ""
    lnd_macaroon_path: str = ""
    lnd_tls_cert_path: str = ""
    lnd_timeout_seconds: float = 8.0
    sqlite_path: str = "lightning_backend.sqlite3"
    max_body_bytes: int = 64 * 1024
    rate_limit_per_minute: int = 120
    status_cache_seconds: float = 2.0
    max_invoice_sats: int = 50_000_000
    max_payment_sats: int = 50_000_000
    default_invoice_expiry_seconds: int = 3600

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_token=os.getenv("KEROSENE_API_TOKEN", ""),
            lnd_rest_url=os.getenv("LIGHTNING_LND_REST_URL", "https://127.0.0.1:8080"),
            lnd_macaroon_hex=os.getenv("LIGHTNING_LND_MACAROON_HEX", ""),
            lnd_macaroon_path=os.getenv("LIGHTNING_LND_MACAROON_PATH", ""),
            lnd_tls_cert_path=os.getenv("LIGHTNING_LND_TLS_CERT_PATH", ""),
            lnd_timeout_seconds=float(os.getenv("LIGHTNING_LND_TIMEOUT_SECONDS", "8")),
            sqlite_path=os.getenv("LIGHTNING_BACKEND_SQLITE", "lightning_backend.sqlite3"),
            max_body_bytes=int(os.getenv("LIGHTNING_BACKEND_MAX_BODY_BYTES", str(64 * 1024))),
            rate_limit_per_minute=int(os.getenv("LIGHTNING_BACKEND_RATE_LIMIT_PER_MINUTE", "120")),
            status_cache_seconds=float(os.getenv("LIGHTNING_BACKEND_STATUS_CACHE_SECONDS", "2")),
            max_invoice_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_INVOICE_SATS", "50000000")),
            max_payment_sats=int(os.getenv("LIGHTNING_BACKEND_MAX_PAYMENT_SATS", "50000000")),
            default_invoice_expiry_seconds=int(os.getenv("LIGHTNING_DEFAULT_INVOICE_EXPIRY_SECONDS", "3600")),
        )

    def validate(self) -> None:
        if len(self.api_token) < 32:
            raise ValueError("KEROSENE_API_TOKEN must be at least 32 characters")
        if not self.lnd_rest_url.startswith(("http://", "https://")):
            raise ValueError("LIGHTNING_LND_REST_URL must use http or https")
        if not self.lnd_macaroon_hex and not self.lnd_macaroon_path:
            raise ValueError("LIGHTNING_LND_MACAROON_HEX or LIGHTNING_LND_MACAROON_PATH is required")
        if self.max_invoice_sats < 1 or self.max_payment_sats < 1:
            raise ValueError("Lightning amount limits must be positive")
