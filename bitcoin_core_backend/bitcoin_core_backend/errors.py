from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass
class RpcError(Exception):
    method: str
    rpc_code: int | None
    message: str
    status_code: int = 502

    def __str__(self) -> str:
        return f"Bitcoin Core RPC {self.method} failed: {self.message}"


def rpc_error_to_api_error(error: RpcError) -> ApiError:
    code = "BITCOIN_RPC_ERROR"
    status = error.status_code
    if error.rpc_code in {-18, -19}:
        code = "BITCOIN_WALLET_NOT_FOUND"
        status = 404
    elif error.rpc_code in {-4, -6}:
        code = "BITCOIN_WALLET_INSUFFICIENT_FUNDS"
        status = 409
    elif error.rpc_code in {-5, -8, -22}:
        code = "BITCOIN_RPC_REJECTED_REQUEST"
        status = 400
    elif error.rpc_code in {-28, -9}:
        code = "BITCOIN_CORE_NOT_READY"
        status = 503
    return ApiError(status, code, str(error), {"rpcCode": error.rpc_code, "method": error.method})
