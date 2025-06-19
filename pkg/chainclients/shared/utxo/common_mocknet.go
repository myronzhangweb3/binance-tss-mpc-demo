//go:build mocknet
// +build mocknet

package utxo

import (
	"binance-tss-mpc-server/common/cosmos"
	"binance-tss-mpc-server/thorclient"
)

func GetConfMulBasisPoint(chain string, bridge thorclient.ThorchainBridge) (cosmos.Uint, error) {
	return cosmos.NewUint(1), nil
}

func MaxConfAdjustment(confirm uint64, chain string, bridge thorclient.ThorchainBridge) (uint64, error) {
	return 1, nil
}
