package tss

import (
	"binance-tss-mpc-server/tss/go-tss/keygen"
	"binance-tss-mpc-server/tss/go-tss/keysign"
)

// Server define the necessary functionality should be provide by a TSS Server implementation
type Server interface {
	Start() error
	Stop()
	GetLocalPeerID() string
	GetKnownPeers() []PeerInfo
	Keygen(req keygen.Request) (keygen.Response, error)
	KeySign(req keysign.Request) (keysign.Response, error)
}
