// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package event_handlers

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math/big"
	"tss-demo/tss_util/comm"
	"tss-demo/tss_util/tss"
	"tss-demo/tss_util/tss/ecdsa/keygen"
)

type KeygenEventHandler struct {
	log           zerolog.Logger
	coordinator   *tss.Coordinator
	host          host.Host
	communication comm.Communication
	storer        keygen.ECDSAKeyshareStorer
	bridgeAddress common.Address
	threshold     int
}

func NewKeygenEventHandler(
	logC zerolog.Context,
	coordinator *tss.Coordinator,
	host host.Host,
	communication comm.Communication,
	storer keygen.ECDSAKeyshareStorer,
	threshold int,
) *KeygenEventHandler {
	return &KeygenEventHandler{
		log:           logC.Logger(),
		coordinator:   coordinator,
		host:          host,
		communication: communication,
		storer:        storer,
		threshold:     threshold,
	}
}

func (eh *KeygenEventHandler) HandleEvents() error {
	eh.log.Info().Msgf("Resolved keygen message")

	key, err := eh.storer.GetKeyshare()
	if (key.Threshold != 0) && (err == nil) {
		return nil
	}

	keygen := keygen.NewKeygen(eh.sessionID(big.NewInt(0)), eh.threshold, eh.host, eh.communication, eh.storer)
	err = eh.coordinator.Execute(context.Background(), []tss.TssProcess{keygen}, make(chan interface{}, 1))
	if err != nil {
		log.Err(err).Msgf("Failed executing keygen")
	}
	return nil
}

func (eh *KeygenEventHandler) sessionID(block *big.Int) string {
	return fmt.Sprintf("keygen-%s", block.String())
}
