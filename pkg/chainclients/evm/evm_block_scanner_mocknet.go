//go:build mocknet
// +build mocknet

package evm

// GetHeight returns the current block height.
func (e *EVMScanner) GetHeight() (int64, error) {
	height, err := e.ethRpc.GetBlockHeight()
	if err != nil {
		return -1, err
	}
	return height, nil
}
