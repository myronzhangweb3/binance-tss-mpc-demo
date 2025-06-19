package keyresharing

import (
	"errors"
	"fmt"
	"github.com/binance-chain/tss-lib/ecdsa/resharing"
	"sync"
	"time"

	bcrypto "github.com/binance-chain/tss-lib/crypto"
	bkg "github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
	btss "github.com/binance-chain/tss-lib/tss"
	tcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"binance-tss-mpc-server/p2p"
	"binance-tss-mpc-server/p2p/conversion"
	"binance-tss-mpc-server/p2p/messages"
	"binance-tss-mpc-server/p2p/storage"
	"binance-tss-mpc-server/tss/go-tss/blame"
	"binance-tss-mpc-server/tss/go-tss/common"
)

type TssKeyResharing struct {
	logger          zerolog.Logger
	localNodePubKey string
	preParams       *bkg.LocalPreParams
	tssCommonStruct *common.TssCommon
	stopChan        chan struct{} // channel to indicate whether we should stop
	localParty      *btss.PartyID
	stateManager    storage.LocalStateManager
	commStopChan    chan struct{}
	p2pComm         *p2p.Communication
}

func NewTssKeyResharing(localP2PID string,
	conf common.TssConfig,
	localNodePubKey string,
	broadcastChan chan *messages.BroadcastMsgChan,
	stopChan chan struct{},
	preParam *bkg.LocalPreParams,
	msgID string,
	stateManager storage.LocalStateManager,
	privateKey tcrypto.PrivKey,
	p2pComm *p2p.Communication,
) *TssKeyResharing {
	return &TssKeyResharing{
		logger: log.With().
			Str("module", "keygen").
			Str("msgID", msgID).Logger(),
		localNodePubKey: localNodePubKey,
		preParams:       preParam,
		tssCommonStruct: common.NewTssCommon(localP2PID, broadcastChan, conf, msgID, privateKey, 1),
		stopChan:        stopChan,
		localParty:      nil,
		stateManager:    stateManager,
		commStopChan:    make(chan struct{}),
		p2pComm:         p2pComm,
	}
}

func (t *TssKeyResharing) GetTssKeyGenChannels() chan *p2p.Message {
	return t.tssCommonStruct.TssMsg
}

func (t *TssKeyResharing) GetTssCommonStruct() *common.TssCommon {
	return t.tssCommonStruct
}

func (t *TssKeyResharing) ResharingNewKey(localStateItem storage.KeygenLocalState, keyResharingReq Request) (*bcrypto.ECPoint, error) {
	partiesID, localPartyID, err := conversion.GetParties(keyResharingReq.Keys, t.localNodePubKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get key resharing parties: %w", err)
	}

	keyResharingLocalStateItem := storage.KeygenLocalState{
		ParticipantKeys: keyResharingReq.Keys,
		LocalPartyKey:   t.localNodePubKey,
	}

	threshold, err := conversion.GetThreshold(len(partiesID))
	if err != nil {
		return nil, err
	}
	keyResharingPartyMap := new(sync.Map)
	ctx := btss.NewPeerContext(partiesID)
	params := tss.NewReSharingParameters(ctx, ctx, localPartyID, len(partiesID), threshold, len(partiesID), threshold)
	outCh := make(chan btss.Message, len(partiesID))
	endCh := make(chan bkg.LocalPartySaveData, len(partiesID))
	errChan := make(chan struct{})
	if t.preParams == nil {
		t.logger.Error().Err(err).Msg("error, empty pre-parameters")
		return nil, errors.New("error, empty pre-parameters")
	}
	blameMgr := t.tssCommonStruct.GetBlameMgr()
	keyResharingParty := resharing.NewLocalParty(params, localStateItem.LocalData, outCh, endCh)
	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	err1 := conversion.SetupIDMaps(partyIDMap, t.tssCommonStruct.PartyIDtoP2PID)
	err2 := conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err1 != nil || err2 != nil {
		t.logger.Error().Msgf("error in creating mapping between partyID and P2P ID")
		return nil, err
	}
	// we never run multi key resharing, so the moniker is set to default empty value
	keyResharingPartyMap.Store("", keyResharingParty)
	partyInfo := &common.PartyInfo{
		PartyMap:   keyResharingPartyMap,
		PartyIDMap: partyIDMap,
	}

	t.tssCommonStruct.SetPartyInfo(partyInfo)
	blameMgr.SetPartyInfo(keyResharingPartyMap, partyIDMap)
	t.tssCommonStruct.P2PPeersLock.Lock()
	t.tssCommonStruct.P2PPeers = conversion.GetPeersID(t.tssCommonStruct.PartyIDtoP2PID, t.tssCommonStruct.GetLocalPeerID())
	t.tssCommonStruct.P2PPeersLock.Unlock()
	var keyResharingWg sync.WaitGroup
	keyResharingWg.Add(2)
	// start key resharing
	go func() {
		defer keyResharingWg.Done()
		defer t.logger.Debug().Msg(">>>>>>>>>>>>>.keyResharingParty started")
		if err := keyResharingParty.Start(); nil != err {
			t.logger.Error().Err(err).Msg("fail to start key resharing party")
			close(errChan)
		}
	}()
	go t.tssCommonStruct.ProcessInboundMessages(t.commStopChan, &keyResharingWg)

	r, err := t.processKeyGen(errChan, outCh, endCh, keyResharingLocalStateItem)
	if err != nil {
		close(t.commStopChan)
		return nil, fmt.Errorf("fail to process key sign: %w", err)
	}
	select {
	case <-time.After(time.Second * 5):
		close(t.commStopChan)

	case <-t.tssCommonStruct.GetTaskDone():
		close(t.commStopChan)
	}

	keyResharingWg.Wait()
	return r, err
}

func (t *TssKeyResharing) processKeyGen(errChan chan struct{},
	outCh <-chan btss.Message,
	endCh <-chan bkg.LocalPartySaveData,
	keyGenLocalStateItem storage.KeygenLocalState,
) (*bcrypto.ECPoint, error) {
	defer t.logger.Debug().Msg("finished keygen process")
	t.logger.Debug().Msg("start to read messages from local party")
	tssConf := t.tssCommonStruct.GetConf()
	blameMgr := t.tssCommonStruct.GetBlameMgr()
	for {
		select {
		case <-errChan: // when keyGenParty return
			t.logger.Error().Msg("key gen failed")
			return nil, errors.New("error channel closed fail to start local party")

		case <-t.stopChan: // when TSS processor receive signal to quit
			return nil, errors.New("received exit signal")

		case <-time.After(tssConf.KeyGenTimeout):
			// we bail out after KeyGenTimeoutSeconds
			t.logger.Error().Msgf("fail to generate message with %s", tssConf.KeyGenTimeout.String())
			lastMsg := blameMgr.GetLastMsg()
			failReason := blameMgr.GetBlame().FailReason
			if failReason == "" {
				failReason = blame.TssTimeout
			}
			if lastMsg == nil {
				t.logger.Error().Msg("fail to start the keygen, the last produced message of this node is none")
				return nil, errors.New("timeout before shared message is generated")
			}
			blameNodesUnicast, err := blameMgr.GetUnicastBlame(messages.KEYGEN2aUnicast)
			if err != nil {
				t.logger.Error().Err(err).Msg("error in get unicast blame")
			}
			t.tssCommonStruct.P2PPeersLock.RLock()
			threshold, err := conversion.GetThreshold(len(t.tssCommonStruct.P2PPeers) + 1)
			t.tssCommonStruct.P2PPeersLock.RUnlock()
			if err != nil {
				t.logger.Error().Err(err).Msg("error in get the threshold to generate blame")
			}

			if len(blameNodesUnicast) > 0 && len(blameNodesUnicast) <= threshold {
				blameMgr.GetBlame().SetBlame(failReason, blameNodesUnicast, true, messages.KEYGEN2aUnicast)
			}
			blameNodesBroadcast, err := blameMgr.GetBroadcastBlame(lastMsg.Type())
			if err != nil {
				t.logger.Error().Err(err).Msg("error in get broadcast blame")
			}
			blameMgr.GetBlame().AddBlameNodes(blameNodesBroadcast...)

			// if we cannot find the blame node, we check whether everyone send me the share
			if len(blameMgr.GetBlame().BlameNodes) == 0 {
				blameNodesMisingShare, isUnicast, err := blameMgr.TssMissingShareBlame(messages.TSSKEYGENROUNDS)
				if err != nil {
					t.logger.Error().Err(err).Msg("fail to get the node of missing share ")
				}
				if len(blameNodesMisingShare) > 0 && len(blameNodesMisingShare) <= threshold {
					blameMgr.GetBlame().AddBlameNodes(blameNodesMisingShare...)
					blameMgr.GetBlame().IsUnicast = isUnicast
				}
			}
			return nil, blame.ErrTssTimeOut

		case msg := <-outCh:
			t.logger.Debug().Msgf(">>>>>>>>>>msg: %s", msg.String())
			blameMgr.SetLastMsg(msg)
			err := t.tssCommonStruct.ProcessOutCh(msg, messages.TSSKeyGenMsg)
			if err != nil {
				t.logger.Error().Err(err).Msg("fail to process the message")
				return nil, err
			}

		case msg := <-endCh:
			t.logger.Debug().Msgf("keygen finished successfully: %s", msg.ECDSAPub.Y().String())
			err := t.tssCommonStruct.NotifyTaskDone()
			if err != nil {
				t.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
			}
			pubKey, _, err := conversion.GetTssPubKey(msg.ECDSAPub)
			if err != nil {
				return nil, fmt.Errorf("fail to get thorchain pubkey: %w", err)
			}
			keyGenLocalStateItem.LocalData = msg
			keyGenLocalStateItem.PubKey = pubKey
			if err := t.stateManager.SaveLocalState(keyGenLocalStateItem); err != nil {
				return nil, fmt.Errorf("fail to save keygen result to storage: %w", err)
			}
			address := t.p2pComm.ExportPeerAddress()
			if err := t.stateManager.SaveAddressBook(address); err != nil {
				t.logger.Error().Err(err).Msg("fail to save the peer addresses")
			}
			return msg.ECDSAPub, nil
		}
	}
}
