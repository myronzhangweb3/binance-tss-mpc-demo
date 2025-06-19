package types

import "binance-tss-mpc-server/common"

type ErrataBlock struct {
	Height int64
	Txs    []ErrataTx
}

type ErrataTx struct {
	TxID  common.TxID
	Chain common.Chain
}
