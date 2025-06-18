// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package event_handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/binance-chain/tss-lib/common"
	common2 "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math/big"
	"tss-demo/tss_util/comm"
	"tss-demo/tss_util/keyshare"
	"tss-demo/tss_util/tss"
	"tss-demo/tss_util/tss/ecdsa/signing"
)

type SignEventHandler struct {
	ctx             context.Context
	log             zerolog.Logger
	coordinator     *tss.Coordinator
	host            host.Host
	communication   comm.Communication
	fetcherBasePath string
}

func NewSignEventHandler(logC zerolog.Context, coordinator *tss.Coordinator, host host.Host, communication comm.Communication, fetcher string) *SignEventHandler {
	return &SignEventHandler{
		ctx:             context.Background(),
		log:             logC.Logger(),
		coordinator:     coordinator,
		host:            host,
		communication:   communication,
		fetcherBasePath: fetcher,
	}
}

func (eh *SignEventHandler) HandleEvents(addr string, hash string) (string, error) {
	eh.log.Info().Msgf("Resolved sign message. addr: %s, hash: %s", addr, hash)

	keyshareStore := keyshare.NewECDSAKeyshareStore(fmt.Sprintf(eh.fetcherBasePath, addr))
	key, err := keyshareStore.GetKeyshare()
	if err != nil {
		return "", err
	}
	address := ethcrypto.PubkeyToAddress(*key.Key.ECDSAPub.ToBtcecPubKey().ToECDSA())
	log.Info().Msgf("HandleEvents MPC key address: %s", address)
	if common2.HexToAddress(addr) != address {
		return "", fmt.Errorf("address mismatch")
	}
	msg := big.NewInt(0)
	hashByte, err := hex.DecodeString(hash)
	if err != nil {
		log.Err(err).Msgf("Failed decoding hash. hash: %s. error: %v", hash, err)
		return "", err
	}
	msg.SetBytes(hashByte)
	sign, err := signing.NewSigning(msg, fmt.Sprintf("msgid-sign-%s", hash), eh.sessionID(addr, hash), eh.host, eh.communication, keyshareStore)
	if err != nil {
		log.Err(err).Msgf("Failed executing sign")
		return "", err
	}
	resultChn := make(chan interface{}, 1)
	err = eh.coordinator.Execute(context.Background(), []tss.TssProcess{sign}, resultChn)
	if err != nil {
		log.Err(err).Msgf("Failed executing sign")
		return "", err
	}
	for {
		select {
		case sig := <-resultChn:
			{
				eh.log.Info().Msgf("Successfully generated signature. sig: %x", sig)
				if sig != nil {
					sigData := sig.(*common.SignatureData)
					return hex.EncodeToString(append(sigData.Signature, sigData.SignatureRecovery...)), nil
				}
				return "", nil
			}
		case <-eh.ctx.Done():
			{
				return "", fmt.Errorf("sign process shutdown")
			}
		}
	}
}

func (eh *SignEventHandler) sessionID(addr string, rlp string) string {
	return fmt.Sprintf("sid-sign-%s-%s", addr, rlp)
}
