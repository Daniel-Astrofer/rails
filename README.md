# Kerosene Rails

Independent Python adapters for external payment rails:

- `bitcoin_core_backend/`: authenticated Bitcoin Core HTTP facade;
- `lightning_flask/`: authenticated LND HTTP facade.

These are separate processes, not Core modules. Runtime and test dependencies
remain separate so production packaging installs only each adapter's
`requirements.txt`.

Documentation: [English](docs/en/README.md) ·
[Português (Brasil)](docs/pt-BR/README.md)

## Validation

Run tests from each adapter directory using an isolated Python environment.
No credential, macaroon, TLS key or environment file belongs in this repository.
