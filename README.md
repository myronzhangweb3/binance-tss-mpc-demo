# Binance TSS Demo Project

This project serves as a demonstration for Threshold Signature Scheme (TSS).

## Overview

The TSS Demo Project is designed to showcase the implementation and functionality of threshold signature schemes, which are crucial for enhancing security in distributed systems. This project leverages key technologies and libraries to provide a robust demonstration of TSS capabilities.

```mermaid
flowchart TD
    A[Start] --> B[Build Transaction Data]
    B --> C[RLP Encode Transaction]
    C --> D[Calculate RLP Hash]

    D --hash--> MPCNode[MPC Signing Network]

    subgraph MPCNode
        direction LR
        N1((Key Share 1)) <---> N2((Key Share 2)) <---> N3((Key Share 3))
        N1 <---> N3
    end

    MPCNode --r,s,v--> E[Generate Distributed Signature]
    E --> F[Collect Signature Result]
    F --> G[Insert Signature into Transaction]
    G --> H[Build Complete Signed Transaction]
    H --> I[Broadcast Transaction to Network]
    I --> J[Transaction Confirmation]
    J --> K[End]

    style A fill:#d0f0c0,stroke:#333,stroke-width:2px
    style MPCNode fill:#f0f0f0,stroke:#333,stroke-width:2px
    style N1 fill:#f9d6c5,stroke:#333,stroke-width:2px,shape:circle
    style N2 fill:#f9d6c5,stroke:#333,stroke-width:2px,shape:circle
    style N3 fill:#f9d6c5,stroke:#333,stroke-width:2px,shape:circle
    style K fill:#f0c0d0,stroke:#333,stroke-width:2px
```

## Related Technologies

- [TSS Library](https://github.com/binance-chain/tss-lib): A library that provides the core functionalities for implementing threshold signature schemes.
- [Sygma Core](https://github.com/sygmaprotocol/sygma-core): A protocol that facilitates cross-chain communication and interoperability.

## Code Reference

For a deeper understanding of the implementation, refer to the [Sygma Relayer v2.6.1](https://github.com/sprintertech/sygma-relayer/tree/v2.6.1) repository, which provides additional context and examples.

## Getting Started

To run the TSS Demo Project, execute the following commands in your terminal:

```bash
TSS_CONFIG=config1.json NAME=p1 PORT=8001 go run cmd/server/main.go
TSS_CONFIG=config2.json NAME=p1 PORT=8002 go run cmd/server/main.go
TSS_CONFIG=config3.json NAME=p1 PORT=8003 go run cmd/server/main.go
```

HTTP API: 
- [health.http](test/http/health.http)
- [genkey.http](test/http/genkey.http)
- [sign.http](test/http/sign.http)

Config and API Params Tools:
- [Generate Peer Private Key](https://github.com/myronzhangweb3/binance-tss-demo/blob/cbc42d77af3909b9ba8a82453234b4d10928bbab/cli/generateKey_test.go#L8)
- [Generate Rlp](https://github.com/myronzhangweb3/binance-tss-demo/blob/930fcc797c283f43400907d6cb3966a8f25b277b/test/tx_build/sign_test.go#L10)
- [Generate Broadcast Tx](https://github.com/myronzhangweb3/binance-tss-demo/blob/930fcc797c283f43400907d6cb3966a8f25b277b/test/tx_build/sign_test.go#L35)