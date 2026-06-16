# Bitcoin Core Flask Backend

Pequeno serviço Flask que expõe uma fachada segura de JSON-RPC do Bitcoin Core para operações de carteira, construção de transações e coesão de dados local.

## Executar

```bash
cd backend/adapters/bitcoin_core_flask
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export KEROSENE_API_TOKEN='replace-with-32-byte-secret'
export BITCOIN_RPC_URL='http://127.0.0.1:8332'
export BITCOIN_RPC_USER='bitcoinrpc'
export BITCOIN_RPC_PASSWORD='rpc-password'
flask --app app:create_app run --host 127.0.0.1 --port 8090
```

Todo endpoint exceto `/health` requer:

```http
Authorization: Bearer $KEROSENE_API_TOKEN
```

Endpoints de mutação aceitam um cabeçalho opcional `Idempotency-Key`. Requisições repetidas com a mesma chave e mesmo corpo retornam a resposta original.

## Endpoints

- `GET /health`
- `GET /v1/node/status`
- `GET /v1/wallets`
- `POST /v1/wallets`
- `GET /v1/wallets/<wallet>/balance`
- `POST /v1/wallets/<wallet>/addresses`
- `GET /v1/wallets/<wallet>/transactions`
- `POST /v1/wallets/<wallet>/transactions/psbt`
- `POST /v1/wallets/<wallet>/transactions/broadcast`
- `GET /v1/cohesion/snapshot`

O serviço intencionalmente constrói PSBTs em vez de assinar e enviar a partir da entrada da requisição. Broadcast aceita apenas hex de transação assinada bruta.
