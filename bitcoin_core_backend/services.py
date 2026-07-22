from __future__ import annotations

from typing import Any

from .config import AppConfig
from .errors import ApiError, RpcError
from .rpc import BitcoinRPCClient
from .store import CohesionStore
from .validation import (
    btc_to_sats,
    normalize_outputs,
    parse_non_negative_int,
    request_fingerprint,
    sats_to_btc_string,
    validate_address_literal,
    validate_address_type,
    validate_label,
    validate_txid,
    validate_wallet_name,
)


class BitcoinBackendService:
    def __init__(self, config: AppConfig, rpc: BitcoinRPCClient, store: CohesionStore) -> None:
        self._config = config
        self._rpc = rpc
        self._store = store

    def node_status(self) -> dict[str, Any]:
        chain = self._rpc.call("getblockchaininfo")
        network = self._rpc.call("getnetworkinfo")
        wallets = self._rpc.call("listwallets")
        return {
            "chain": chain.get("chain"),
            "blocks": chain.get("blocks"),
            "headers": chain.get("headers"),
            "verificationProgress": chain.get("verificationprogress"),
            "initialBlockDownload": chain.get("initialblockdownload"),
            "pruned": chain.get("pruned"),
            "connections": network.get("connections"),
            "networkActive": network.get("networkactive"),
            "loadedWallets": wallets,
        }

    def open_wallet(self, body: dict[str, Any]) -> dict[str, Any]:
        wallet = validate_wallet_name(body.get("name") or self._config.default_wallet)
        create_if_missing = bool(body.get("createIfMissing", False))
        disable_private_keys = bool(body.get("disablePrivateKeys", False))
        blank = bool(body.get("blank", False))

        loaded = self._rpc.call("listwallets")
        if wallet in loaded:
            return {"wallet": wallet, "loaded": True, "created": False}

        try:
            self._rpc.call("loadwallet", [wallet])
            return {"wallet": wallet, "loaded": True, "created": False}
        except RpcError as exc:
            if exc.rpc_code != -18 or not create_if_missing:
                raise

        if not self._config.allow_wallet_create:
            raise ApiError(
                403,
                "WALLET_CREATE_DISABLED",
                "Wallet creation is disabled. Set BITCOIN_BACKEND_ALLOW_WALLET_CREATE=true to enable it.",
            )
        result = self._rpc.call(
            "createwallet",
            [wallet, disable_private_keys, blank, "", True, True, True],
        )
        return {
            "wallet": wallet,
            "loaded": True,
            "created": True,
            "warning": result.get("warning") if isinstance(result, dict) else None,
        }

    def wallet_balance(self, wallet_name: str) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet_name)
        balances = self._rpc.call("getbalances", wallet=wallet)
        info = self._rpc.call("getwalletinfo", wallet=wallet)
        mine = balances.get("mine", {})
        return {
            "wallet": wallet,
            "txCount": info.get("txcount"),
            "keypoolOldest": info.get("keypoololdest"),
            "privateKeysEnabled": bool(info.get("private_keys_enabled", True)),
            "avoidReuse": info.get("avoid_reuse"),
            "trustedSats": btc_to_sats(mine.get("trusted", 0)),
            "untrustedPendingSats": btc_to_sats(mine.get("untrusted_pending", 0)),
            "immatureSats": btc_to_sats(mine.get("immature", 0)),
        }

    def new_address(self, wallet_name: str, body: dict[str, Any]) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet_name)
        label = validate_label(body.get("label"), "")
        address_type = validate_address_type(body.get("addressType"))
        address = self._rpc.call("getnewaddress", [label, address_type], wallet=wallet)
        validation = self._rpc.call("validateaddress", [address])
        return {
            "wallet": wallet,
            "address": address,
            "addressType": address_type,
            "label": label,
            "isValid": bool(validation.get("isvalid")),
        }

    def list_utxos(self, wallet_name: str, query: dict[str, Any]) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet_name)
        min_conf = parse_non_negative_int(
            query.get("minConfirmations"),
            "minConfirmations",
            self._config.default_min_confirmations,
            9999999,
        )
        max_count = parse_non_negative_int(query.get("limit"), "limit", 100, 500)
        utxos = self._rpc.call("listunspent", [min_conf, 9999999, [], True], wallet=wallet)
        compact = []
        for utxo in utxos[:max_count]:
            compact.append(
                {
                    "txid": utxo.get("txid"),
                    "vout": utxo.get("vout"),
                    "address": utxo.get("address"),
                    "amountSats": btc_to_sats(utxo.get("amount", 0)),
                    "confirmations": utxo.get("confirmations"),
                    "spendable": utxo.get("spendable"),
                    "solvable": utxo.get("solvable"),
                    "safe": utxo.get("safe"),
                    "reused": utxo.get("reused", False),
                }
            )
        return {"wallet": wallet, "minConfirmations": min_conf, "utxos": compact}

    def create_psbt(
        self,
        wallet_name: str,
        body: dict[str, Any],
        *,
        idempotency_key: str | None,
        request_hash: str,
    ) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet_name)
        outputs = normalize_outputs(body, self._config.max_outputs_per_tx, self._config.max_send_sats)
        self._validate_outputs_on_core(outputs)

        options = self._funding_options(body)
        core_outputs = [{item["address"]: sats_to_btc_string(item["amountSats"])} for item in outputs]
        result = self._rpc.call("walletcreatefundedpsbt", [[], core_outputs, 0, options, True], wallet=wallet)
        fee_sats = btc_to_sats(result.get("fee", 0))
        total_sats = sum(item["amountSats"] for item in outputs)
        record_id = self._store.record_transaction(
            wallet=wallet,
            kind="psbt",
            request_hash=request_hash,
            idempotency_key=idempotency_key,
            outputs=outputs,
            psbt=result.get("psbt"),
            status="created",
            metadata={"feeSats": fee_sats, "changePosition": result.get("changepos")},
        )
        return {
            "recordId": record_id,
            "wallet": wallet,
            "psbt": result.get("psbt"),
            "feeSats": fee_sats,
            "totalOutputSats": total_sats,
            "changePosition": result.get("changepos"),
            "complete": False,
        }

    def create_sign_and_send(
        self,
        wallet_name: str,
        body: dict[str, Any],
        *,
        idempotency_key: str | None,
        request_hash: str,
    ) -> dict[str, Any]:
        if not self._config.allow_broadcast:
            raise ApiError(
                403,
                "BROADCAST_DISABLED",
                "Broadcasting is disabled. Set BITCOIN_BACKEND_ALLOW_BROADCAST=true to enable it.",
            )
        if not idempotency_key:
            raise ApiError(428, "IDEMPOTENCY_REQUIRED", "Idempotency-Key is required for broadcast requests.")
        if body.get("confirmBroadcast") is not True:
            raise ApiError(400, "BROADCAST_CONFIRMATION_REQUIRED", "confirmBroadcast must be true.")

        psbt_response = self.create_psbt(
            wallet_name,
            body,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        wallet = psbt_response["wallet"]
        processed = self._rpc.call("walletprocesspsbt", [psbt_response["psbt"], True, "ALL", False], wallet=wallet)
        finalized = self._rpc.call("finalizepsbt", [processed.get("psbt"), True])
        if not finalized.get("complete") or not finalized.get("hex"):
            raise ApiError(409, "PSBT_NOT_FINAL", "Bitcoin Core could not finalize the PSBT.")

        raw_tx = finalized["hex"]
        mempool = self._rpc.call("testmempoolaccept", [[raw_tx]])
        first = mempool[0] if mempool else {}
        if not first.get("allowed"):
            raise ApiError(
                409,
                "MEMPOOL_REJECTED",
                "Bitcoin Core rejected the transaction.",
                {"rejectReason": first.get("reject-reason")},
            )
        txid = self._rpc.call("sendrawtransaction", [raw_tx])
        record_id = self._store.record_transaction(
            wallet=wallet,
            kind="broadcast",
            request_hash=request_hash,
            idempotency_key=idempotency_key,
            outputs=normalize_outputs(body, self._config.max_outputs_per_tx, self._config.max_send_sats),
            psbt=processed.get("psbt"),
            raw_tx=raw_tx,
            txid=txid,
            status="broadcast",
            metadata={"mempoolAllowed": True, "feeSats": psbt_response.get("feeSats")},
        )
        return {
            "recordId": record_id,
            "wallet": wallet,
            "txid": txid,
            "feeSats": psbt_response.get("feeSats"),
            "totalOutputSats": psbt_response.get("totalOutputSats"),
            "mempoolAccepted": True,
        }

    def wallet_transaction(self, wallet_name: str, txid_value: str) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet_name)
        txid = validate_txid(txid_value)
        tx = self._rpc.call("gettransaction", [txid, True, True], wallet=wallet)
        return {
            "wallet": wallet,
            "txid": tx.get("txid", txid),
            "amountSats": btc_to_sats(tx.get("amount", 0)),
            "feeSats": btc_to_sats(tx.get("fee", 0)) if tx.get("fee") is not None else None,
            "confirmations": tx.get("confirmations", 0),
            "trusted": tx.get("trusted"),
            "details": tx.get("details", []),
            "blockhash": tx.get("blockhash"),
            "time": tx.get("time"),
            "bip125Replaceable": tx.get("bip125-replaceable"),
        }

    def cohesion_status(self, wallet_name: str | None = None) -> dict[str, Any]:
        wallet = validate_wallet_name(wallet_name or self._config.default_wallet)
        chain = self._rpc.call("getblockchaininfo")
        loaded_wallets = self._rpc.call("listwallets")
        wallet_loaded = wallet in loaded_wallets
        store_summary = self._store.summary()
        recent = self._store.recent_transactions(wallet if wallet_loaded else None, limit=10)
        return {
            "wallet": wallet,
            "checks": {
                "rpcReachable": True,
                "walletLoaded": wallet_loaded,
                "chainKnown": bool(chain.get("chain")),
                "initialBlockDownload": bool(chain.get("initialblockdownload")),
                "localStateWritable": True,
            },
            "chain": {
                "name": chain.get("chain"),
                "blocks": chain.get("blocks"),
                "headers": chain.get("headers"),
                "verificationProgress": chain.get("verificationprogress"),
            },
            "state": store_summary,
            "recentTransactions": recent,
        }

    def _validate_outputs_on_core(self, outputs: list[dict[str, Any]]) -> None:
        for item in outputs:
            address = validate_address_literal(item["address"])
            result = self._rpc.call("validateaddress", [address])
            if not result.get("isvalid"):
                raise ApiError(400, "INVALID_BITCOIN_ADDRESS", "Bitcoin Core rejected an output address.")

    def _funding_options(self, body: dict[str, Any]) -> dict[str, Any]:
        conf_target = parse_non_negative_int(body.get("confTarget"), "confTarget", 6, 1008)
        if conf_target == 0:
            conf_target = 6
        estimate_mode = str(body.get("estimateMode") or "economical").upper()
        if estimate_mode not in {"UNSET", "ECONOMICAL", "CONSERVATIVE"}:
            raise ApiError(400, "INVALID_ESTIMATE_MODE", "estimateMode must be economical or conservative.")

        subtract = body.get("subtractFeeFromOutputs", [])
        if subtract is None:
            subtract = []
        if not isinstance(subtract, list) or any(not isinstance(index, int) for index in subtract):
            raise ApiError(400, "INVALID_SUBTRACT_FEE", "subtractFeeFromOutputs must be a list of output indexes.")

        return {
            "conf_target": conf_target,
            "estimate_mode": estimate_mode,
            "replaceable": bool(body.get("replaceable", True)),
            "lockUnspents": bool(body.get("lockUnspents", False)),
            "subtractFeeFromOutputs": subtract,
            "change_type": str(body.get("changeType") or "bech32"),
        }


def fingerprint_for_request(method: str, path: str, body: dict[str, Any] | None) -> str:
    return request_fingerprint(method, path, body or {})
