//go:build mocknet
// +build mocknet

package ethereum

import "binance-tss-mpc-server/common"

const (
	// initialGasPrice overrides the initial gas price in mocknet to force a reported fee.
	initialGasPrice = 2 * common.One * 100
)
