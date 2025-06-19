package main

import (
	"binance-tss-mpc-server/tss/go-tss/keyresharing"
	"errors"

	"binance-tss-mpc-server/p2p/conversion"
	"binance-tss-mpc-server/tss/go-tss/blame"
	"binance-tss-mpc-server/tss/go-tss/common"
	"binance-tss-mpc-server/tss/go-tss/keygen"
	"binance-tss-mpc-server/tss/go-tss/keysign"
	"binance-tss-mpc-server/tss/go-tss/tss"
)

type MockTssServer struct {
	failToStart   bool
	failToKeyGen  bool
	failToKeySign bool
}

func (mts *MockTssServer) Start() error {
	if mts.failToStart {
		return errors.New("you ask for it")
	}
	return nil
}

func (mts *MockTssServer) Stop() {
}

func (mts *MockTssServer) GetLocalPeerID() string {
	return conversion.GetRandomPeerID().String()
}

func (mts *MockTssServer) GetKnownPeers() []tss.PeerInfo {
	return []tss.PeerInfo{}
}

func (mts *MockTssServer) Keygen(req keygen.Request) (keygen.Response, error) {
	if mts.failToKeyGen {
		return keygen.Response{}, errors.New("you ask for it")
	}
	return keygen.NewResponse(conversion.GetRandomPubKey(), "whatever", common.Success, blame.Blame{}), nil
}

func (mts *MockTssServer) KeySign(req keysign.Request) (keysign.Response, error) {
	if mts.failToKeySign {
		return keysign.Response{}, errors.New("you ask for it")
	}
	newSig := keysign.NewSignature("", "", "", "", "")
	return keysign.NewResponse([]keysign.Signature{newSig}, common.Success, blame.Blame{}), nil
}

func (mts *MockTssServer) KeyResharing(req keyresharing.Request) (keyresharing.Response, error) {
	if mts.failToKeyGen {
		return keyresharing.Response{}, errors.New("you ask for it")
	}
	return keyresharing.NewResponse(conversion.GetRandomPubKey(), "whatever", common.Success, blame.Blame{}), nil
}
