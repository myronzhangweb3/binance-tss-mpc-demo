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
	"tss-demo/tss_util/comm"
	"tss-demo/tss_util/tss"
	"tss-demo/tss_util/tss/ecdsa/keygen"
)

type KeygenEventHandler struct {
	ctx           context.Context
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
		ctx:           context.Background(),
		log:           logC.Logger(),
		coordinator:   coordinator,
		host:          host,
		communication: communication,
		storer:        storer,
		threshold:     threshold,
	}
}

func (eh *KeygenEventHandler) HandleEvents(sid string) (string, error) {
	eh.log.Info().Msgf("Resolved keygen message")

	key, err := eh.storer.GetKeyshare()
	if (key.Threshold != 0) && (err == nil) {
		eh.log.Info().Msgf("Already resolved keygen message")
		return "", nil
	}

	keygen := keygen.NewKeygen(eh.sessionID(sid), eh.threshold, eh.host, eh.communication, eh.storer)
	resultChn := make(chan interface{}, 1)
	err = eh.coordinator.Execute(context.Background(), []tss.TssProcess{keygen}, resultChn)
	if err != nil {
		log.Err(err).Msgf("Failed executing keygen")
	}

	for {
		select {
		case res := <-resultChn:
			{
				eh.log.Info().Msgf("Successfully generated keyshare. address: %s", res)
				return res.(string), nil
			}
		case <-eh.ctx.Done():
			{
				return "", fmt.Errorf("keygen process shutdown")
			}
		}
	}
}

func (eh *KeygenEventHandler) sessionID(sid string) string {
	return fmt.Sprintf("keygen-%s", sid)
}
