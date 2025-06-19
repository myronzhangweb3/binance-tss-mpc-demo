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
- [Thorchain](https://gitlab.com/thorchain/thornode/-/tree/v3.7.0/bifrost/tss/go-tss?ref_type=tags)

## Code Reference

For a deeper understanding of the implementation, refer to the [Thorchain v3.7.0](https://gitlab.com/thorchain/thornode/-/tree/v3.7.0/bifrost/tss/go-tss?ref_type=tag) repository, which provides additional context and examples.

## Getting Started

### Start Server
To run the TSS Demo Project, execute the following commands in your terminal:


```bash
# thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae
go run cmd/tss-recovery/main.go --tss-port 127.0.0.1:8081 --pretty-log --p2p-port 6671 --home ./data/node1 --peer /ip4/127.0.0.1/tcp/6672/p2p/16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ --peer /ip4/127.0.0.1/tcp/6673/p2p/16Uiu2HAm7JvHh9HhWUy3sVBYzPcVJTmDFbGxQ1dnBWgCRzfN1TXM
# node secret key: NmI4NmIyNzNmZjM0ZmNlMTlkNmI4MDRlZmY1YTNmNTc0N2FkYTRlYWEyMmYxZDQ5YzAxZTUyZGRiNzg3NWI0Yg==

# thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0
go run cmd/tss-recovery/main.go --tss-port 127.0.0.1:8082 --pretty-log --p2p-port 6672 --home ./data/node2 --peer /ip4/127.0.0.1/tcp/6671/p2p/16Uiu2HAmVkKntsECaYfefR1V2yCR79CegLATuTPE6B9TxgxBiiiA --peer /ip4/127.0.0.1/tcp/6673/p2p/16Uiu2HAm7JvHh9HhWUy3sVBYzPcVJTmDFbGxQ1dnBWgCRzfN1TXM
# node secret key: ZDQ3MzVlM2EyNjVlMTZlZWUwM2Y1OTcxOGI5YjVkMDMwMTljMDdkOGI2YzUxZjkwZGEzYTY2NmVlYzEzYWIzNQ==

# thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf
go run cmd/tss-recovery/main.go --tss-port 127.0.0.1:8083 --pretty-log --p2p-port 6673 --home ./data/node3 --peer /ip4/127.0.0.1/tcp/6671/p2p/16Uiu2HAmVkKntsECaYfefR1V2yCR79CegLATuTPE6B9TxgxBiiiA --peer /ip4/127.0.0.1/tcp/6672/p2p/16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ 
# node secret key: NGUwNzQwODU2MmJlZGI4YjYwY2UwNWMxZGVjZmUzYWQxNmI3MjIzMDk2N2RlMDFmNjQwYjdlNDcyOWI0OWZjZQ==

```

### Generate Key

[api_test.go](cmd/tss/api_test.go)

```bash
curl --location --request GET 'http://127.0.0.1:8001/api/v1/deriving/0x3D3A3B117a2f2393FBcdF95e9DA47c1166b469e7/key1'
```

###  Sign

[api_test.go](cmd/tss/api_test.go)

