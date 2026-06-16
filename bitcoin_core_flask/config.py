from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_token: str
    rpc_url: str
    rpc_user: str
    rpc_password: str
    rpc_timeout_seconds: float = 8.0
    sqlite_path: str = "bitcoin_core_backend.sqlite3"
    max_body_bytes: int = 64 * 1024
    rate_limit_per_minute: int = 120
    status_cache_seconds: float = 2.0

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_token=os.getenv("KEROSENE_API_TOKEN", ""),
            rpc_url=os.getenv("BITCOIN_RPC_URL", "http://127.0.0.1:8332"),
            rpc_user=os.getenv("BITCOIN_RPC_USER", ""),
            rpc_password=os.getenv("BITCOIN_RPC_PASSWORD", ""),
            rpc_timeout_seconds=float(os.getenv("BITCOIN_RPC_TIMEOUT_SECONDS", "8")),
            sqlite_path=os.getenv("BITCOIN_BACKEND_SQLITE", "bitcoin_core_backend.sqlite3"),
            max_body_bytes=int(os.getenv("BITCOIN_BACKEND_MAX_BODY_BYTES", str(64 * 1024))),
            rate_limit_per_minute=int(os.getenv("BITCOIN_BACKEND_RATE_LIMIT_PER_MINUTE", "120")),
            status_cache_seconds=float(os.getenv("BITCOIN_BACKEND_STATUS_CACHE_SECONDS", "2")),
        )

    def validate(self) -> None:
        if len(self.api_token) < 32:
            raise ValueError("KEROSENE_API_TOKEN must be at least 32 characters")
        if not self.rpc_url.startswith(("http://", "https://")):
            raise ValueError("BITCOIN_RPC_URL must use http or https")
        if not self.rpc_user or not self.rpc_password:
            raise ValueError("BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD are required")
