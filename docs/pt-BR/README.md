# Kerosene Rails

Este repositório reúne somente os adaptadores que traduzem chamadas dos
serviços Kerosene para redes financeiras externas.

- `bitcoin_core_backend`: fachada HTTP do Bitcoin Core; 17 testes.
- `lightning_flask`: fachada HTTP do LND; 32 testes.

Cada adapter roda como processo Python independente. O `kerosene-deploy` será
responsável pelas imagens e configurações de execução; o Core deve consumir os
contratos sem incorporar este código.

Pendente: definir imagens imutáveis no Deploy, criar testes de contrato com o
KFE e criar o remoto no GitHub. A implementação de mTLS fica para a próxima
fase, conforme solicitado.
