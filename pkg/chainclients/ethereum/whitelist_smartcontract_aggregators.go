package ethereum

import (
	"binance-tss-mpc-server/common"
	"binance-tss-mpc-server/x/thorchain/aggregators"
)

func LatestAggregatorContracts() []common.Address {
	addrs := []common.Address{}
	for _, agg := range aggregators.DexAggregators() {
		if agg.Chain.Equals(common.ETHChain) {
			addrs = append(addrs, common.Address(agg.Address))
		}
	}
	return addrs
}
