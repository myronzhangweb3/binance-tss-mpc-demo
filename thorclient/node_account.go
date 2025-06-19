package thorclient

import (
	"encoding/json"
	"fmt"

	"binance-tss-mpc-server/x/thorchain/types"
)

// GetNodeAccount retrieves node account for this address from thorchain
func (b *thorchainBridge) GetNodeAccount(thorAddr string) (*types.NodeAccount, error) {
	path := fmt.Sprintf("%s/%s", NodeAccountEndpoint, thorAddr)
	body, _, err := b.getWithPath(path)
	if err != nil {
		return &types.NodeAccount{}, fmt.Errorf("failed to get node account: %w", err)
	}
	var na types.NodeAccount
	if err = json.Unmarshal(body, &na); err != nil {
		return &types.NodeAccount{}, fmt.Errorf("failed to unmarshal node account: %w", err)
	}
	return &na, nil
}

// GetNodeAccounts retrieves all node accounts from thorchain
func (b *thorchainBridge) GetNodeAccounts() ([]*types.NodeAccount, error) {
	path := NodeAccountsEndpoint
	body, _, err := b.getWithPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get node account: %w", err)
	}
	var na []*types.NodeAccount
	if err = json.Unmarshal(body, &na); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node accounts: %w", err)
	}
	return na, nil
}
