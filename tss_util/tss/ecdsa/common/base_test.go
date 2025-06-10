// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package common_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
	comm2 "tss-demo/tss_util/comm"
	mock_communication "tss-demo/tss_util/comm/mock"
	common2 "tss-demo/tss_util/tss/ecdsa/common"
	mock_tss2 "tss-demo/tss_util/tss/ecdsa/common/mock"
	"tss-demo/tss_util/tss/message"

	"github.com/binance-chain/tss-lib/tss"
	"github.com/golang/mock/gomock"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/sourcegraph/conc/pool"
	"github.com/stretchr/testify/suite"
)

type BaseTssTestSuite struct {
	suite.Suite
	gomockController  *gomock.Controller
	mockMessage       *mock_tss2.MockMessage
	mockCommunication *mock_communication.MockCommunication
	mockParty         *mock_tss2.MockParty
}

func TestRunBaseTssTestSuite(t *testing.T) {
	suite.Run(t, new(BaseTssTestSuite))
}

func (s *BaseTssTestSuite) SetupTest() {
	s.gomockController = gomock.NewController(s.T())
	s.mockMessage = mock_tss2.NewMockMessage(s.gomockController)
	s.mockParty = mock_tss2.NewMockParty(s.gomockController)
	s.mockCommunication = mock_communication.NewMockCommunication(s.gomockController)
}

func (s *BaseTssTestSuite) Test_BroadcastPeers_BroadcastMessage() {
	peerID1, _ := peer.Decode("QmcW3oMdSqoEcjbyd51auqC23vhKX6BqfcZcY2HJ3sKAZR")
	peerID2, _ := peer.Decode("QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54")
	baseTss := common2.BaseTss{
		Peers: []peer.ID{peerID1, peerID2},
	}
	s.mockMessage.EXPECT().IsBroadcast().Return(true)

	broadcastPeers, err := baseTss.BroadcastPeers(s.mockMessage)

	s.Nil(err)
	s.Equal(broadcastPeers, []peer.ID{peerID1, peerID2})
}

func (s *BaseTssTestSuite) Test_BroadcastPeers_TargetedMessage() {
	peerID1, _ := peer.Decode("QmcW3oMdSqoEcjbyd51auqC23vhKX6BqfcZcY2HJ3sKAZR")
	peerID2, _ := peer.Decode("QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54")
	baseTss := common2.BaseTss{
		Peers: []peer.ID{peerID1, peerID2},
	}
	s.mockMessage.EXPECT().IsBroadcast().Return(false)
	s.mockMessage.EXPECT().GetTo().Return([]*tss.PartyID{common2.CreatePartyID("QmcW3oMdSqoEcjbyd51auqC23vhKX6BqfcZcY2HJ3sKAZR")})

	broadcastPeers, err := baseTss.BroadcastPeers(s.mockMessage)

	s.Nil(err)
	s.Equal(broadcastPeers, []peer.ID{peerID1})
}

func (s *BaseTssTestSuite) Test_PopulatePartyStore() {
	baseTss := common2.BaseTss{
		PartyStore: make(map[string]*tss.PartyID),
	}
	peerID1 := "QmcW3oMdSqoEcjbyd51auqC23vhKX6BqfcZcY2HJ3sKAZR"
	peerID2 := "QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54"
	parties := []*tss.PartyID{common2.CreatePartyID(peerID1), common2.CreatePartyID(peerID2)}

	baseTss.PopulatePartyStore(parties)

	s.Equal(baseTss.PartyStore[peerID1], common2.CreatePartyID(peerID1))
}

func (s *BaseTssTestSuite) Test_ProcessOutboundMessages_InvalidWireBytes() {
	outChn := make(chan tss.Message)
	baseTss := common2.BaseTss{}
	s.mockMessage.EXPECT().String().Return("MSG")
	s.mockMessage.EXPECT().WireBytes().Return([]byte{}, &tss.MessageRouting{}, errors.New("error"))

	p := pool.New().WithContext(context.Background()).WithCancelOnError()
	p.Go(func(ctx context.Context) error {
		return baseTss.ProcessOutboundMessages(ctx, outChn, comm2.TssKeyGenMsg)
	})
	outChn <- s.mockMessage
	err := p.Wait()

	s.NotNil(err)
}

func (s *BaseTssTestSuite) Test_ProcessOutboundMessages_InvalidBroadcastPeers() {
	outChn := make(chan tss.Message)
	baseTss := common2.BaseTss{}
	s.mockMessage.EXPECT().WireBytes().Return([]byte{}, &tss.MessageRouting{
		IsBroadcast: true,
		From:        common2.CreatePartyID("invalid"),
	}, nil)
	s.mockMessage.EXPECT().String().Return("MSG")
	s.mockMessage.EXPECT().IsBroadcast().Return(false)
	s.mockMessage.EXPECT().GetTo().Return([]*tss.PartyID{common2.CreatePartyID("invalid")})

	ctx, cancel := context.WithCancel(context.Background())
	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error {
		return baseTss.ProcessOutboundMessages(ctx, outChn, comm2.TssKeyGenMsg)
	})
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	outChn <- s.mockMessage
	err := p.Wait()

	s.NotNil(err)
}

func (s *BaseTssTestSuite) Test_ProcessOutboundMessages_ValidMessage() {
	outChn := make(chan tss.Message)
	peerID, _ := peer.Decode("QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54")
	baseTss := common2.BaseTss{
		Peers:         []peer.ID{peerID},
		SID:           "keygen",
		Communication: s.mockCommunication,
	}
	s.mockMessage.EXPECT().String().Return("MSG")
	s.mockMessage.EXPECT().WireBytes().Return([]byte{}, &tss.MessageRouting{
		IsBroadcast: true,
		From:        common2.CreatePartyID("QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54"),
	}, nil)
	s.mockMessage.EXPECT().IsBroadcast().Return(true)
	s.mockCommunication.EXPECT().Broadcast(baseTss.Peers, gomock.Any(), comm2.TssKeyGenMsg, "keygen").Return(nil)

	ctx, cancel := context.WithCancel(context.Background())
	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error {
		return baseTss.ProcessOutboundMessages(ctx, outChn, comm2.TssKeyGenMsg)
	})
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	outChn <- s.mockMessage

	err := p.Wait()
	s.Nil(err)
}

func (s *BaseTssTestSuite) Test_ProcessOutboundMessages_ContextCanceled() {
	outChn := make(chan tss.Message, 1)
	peerID, _ := peer.Decode("QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54")
	baseTss := common2.BaseTss{
		Peers: []peer.ID{peerID},
	}
	s.mockMessage.EXPECT().WireBytes().Return([]byte{}, &tss.MessageRouting{
		IsBroadcast: true,
		From:        common2.CreatePartyID("QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54"),
	}, errors.New("error")).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error {
		return baseTss.ProcessOutboundMessages(ctx, outChn, comm2.TssKeyGenMsg)
	})
	cancel()

	err := p.Wait()
	s.Nil(err)
}

func (s *BaseTssTestSuite) Test_ProcessInboundMessages_InvalidMessage() {
	msgChan := make(chan *comm2.WrappedMessage)
	partyStore := make(map[string]*tss.PartyID)
	peerID := "QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54"
	party := common2.CreatePartyID(peerID)
	partyStore[peerID] = party
	baseTss := common2.BaseTss{
		PartyStore: partyStore,
		Party:      s.mockParty,
		SID:        "sessionID",
	}
	msg, _ := message.MarshalTssMessage([]byte{1}, true)
	peer, _ := peer.Decode(peerID)
	wrappedMsg := &comm2.WrappedMessage{
		Payload: msg,
		From:    peer,
	}
	s.mockParty.EXPECT().UpdateFromBytes([]byte{1}, baseTss.PartyStore[peerID], true, new(big.Int).SetBytes([]byte(baseTss.SID))).Return(false, tss.NewError(fmt.Errorf("error"), "", 1, &tss.PartyID{}))

	p := pool.New().WithContext(context.Background()).WithCancelOnError()
	p.Go(func(ctx context.Context) error { return baseTss.ProcessInboundMessages(ctx, msgChan) })

	msgChan <- wrappedMsg

	err := p.Wait()
	s.NotNil(err)
}

func (s *BaseTssTestSuite) Test_ProcessInboundMessages_ValidMessage() {
	msgChan := make(chan *comm2.WrappedMessage)
	partyStore := make(map[string]*tss.PartyID)
	peerID := "QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54"
	party := common2.CreatePartyID(peerID)
	partyStore[peerID] = party
	baseTss := common2.BaseTss{
		PartyStore: partyStore,
		Party:      s.mockParty,
		SID:        "sessionID",
	}
	msg, _ := message.MarshalTssMessage([]byte{1}, true)
	peer, _ := peer.Decode(peerID)
	wrappedMsg := &comm2.WrappedMessage{
		Payload: msg,
		From:    peer,
	}
	s.mockParty.EXPECT().UpdateFromBytes([]byte{1}, baseTss.PartyStore[peerID], true, new(big.Int).SetBytes([]byte(baseTss.SID))).Return(true, nil).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error { return baseTss.ProcessInboundMessages(ctx, msgChan) })

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	msgChan <- wrappedMsg

	err := p.Wait()
	s.Nil(err)
}

func (s *BaseTssTestSuite) Test_ProcessInboundMessages_ContextCanceled() {
	msgChan := make(chan *comm2.WrappedMessage, 1)
	partyStore := make(map[string]*tss.PartyID)
	peerID := "QmZHPnN3CKiTAp8VaJqszbf8m7v4mPh15M421KpVdYHF54"
	party := common2.CreatePartyID(peerID)
	partyStore[peerID] = party
	baseTss := common2.BaseTss{
		PartyStore: partyStore,
		Party:      s.mockParty,
		SID:        "sessionID",
	}
	s.mockParty.EXPECT().UpdateFromBytes([]byte{1}, baseTss.PartyStore[peerID], true, new(big.Int).SetBytes([]byte(baseTss.SID))).Return(false, &tss.Error{}).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error { return baseTss.ProcessInboundMessages(ctx, msgChan) })

	cancel()

	err := p.Wait()
	s.Nil(err)
}
