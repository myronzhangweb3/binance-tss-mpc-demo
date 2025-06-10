# TSS Demo

This is a demo project for TSS.

Related technologies:
- github.com/binance-chain/tss-lib
- github.com/sygmaprotocol/sygma-core

Code Reference: https://github.com/sprintertech/sygma-relayer/tree/v2.6.1


## Run
```bash
TSS_CONFIG=config1.json;NAME=p1;PORT=8001;BLOCKSTORE=data/blockstore1 go run cmd/server/main.go
TSS_CONFIG=config2.json;NAME=p1;PORT=8002;BLOCKSTORE=data/blockstore2 go run cmd/server/main.go
TSS_CONFIG=config3.json;NAME=p1;PORT=8003;BLOCKSTORE=data/blockstore3 go run cmd/server/main.go
```

http api call: [api.http](api.http)
