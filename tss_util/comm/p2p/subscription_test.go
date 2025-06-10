// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package p2p_test

import (
	"testing"
	comm2 "tss-demo/tss_util/comm"
	"tss-demo/tss_util/comm/p2p"

	"github.com/stretchr/testify/suite"
)

type SessionSubscriptionManagerTestSuite struct {
	suite.Suite
}

func TestRunSessionSubscriptionManagerTestSuite(t *testing.T) {
	suite.Run(t, new(SessionSubscriptionManagerTestSuite))
}

func (s *SessionSubscriptionManagerTestSuite) SetupSuite()    {}
func (s *SessionSubscriptionManagerTestSuite) TearDownSuite() {}
func (s *SessionSubscriptionManagerTestSuite) SetupTest() {

}
func (s *SessionSubscriptionManagerTestSuite) TearDownTest() {}

func (s *SessionSubscriptionManagerTestSuite) TestSessionSubscriptionManager_ManageSingleSubscribe_Success() {
	subscriptionManager := p2p.NewSessionSubscriptionManager()

	sChannel := make(chan *comm2.WrappedMessage)
	subscriptionID := subscriptionManager.SubscribeTo("1", comm2.CoordinatorPingMsg, sChannel)
	subscribers := subscriptionManager.GetSubscribers("1", comm2.CoordinatorPingMsg)
	s.Len(subscribers, 1)

	subscriptionManager.UnSubscribeFrom(subscriptionID)
	subscribers = subscriptionManager.GetSubscribers("1", comm2.CoordinatorPingMsg)
	s.Len(subscribers, 0)
}

func (s *SessionSubscriptionManagerTestSuite) TestSessionSubscriptionManager_ManageMultipleSubscribe_Success() {
	subscriptionManager := p2p.NewSessionSubscriptionManager()

	sub1Channel := make(chan *comm2.WrappedMessage)
	subscriptionID1 := subscriptionManager.SubscribeTo("1", comm2.CoordinatorPingMsg, sub1Channel)

	sub2Channel := make(chan *comm2.WrappedMessage)
	_ = subscriptionManager.SubscribeTo("1", comm2.CoordinatorPingMsg, sub2Channel)

	sub3Channel := make(chan *comm2.WrappedMessage)
	subscriptionID3 := subscriptionManager.SubscribeTo("2", comm2.CoordinatorPingMsg, sub3Channel)

	subscribers := subscriptionManager.GetSubscribers("1", comm2.CoordinatorPingMsg)
	s.Len(subscribers, 2)

	subscribers = subscriptionManager.GetSubscribers("2", comm2.CoordinatorPingMsg)
	s.Len(subscribers, 1)

	subscriptionManager.UnSubscribeFrom(subscriptionID1)
	subscriptionManager.UnSubscribeFrom(subscriptionID3)

	subscribers = subscriptionManager.GetSubscribers("1", comm2.CoordinatorPingMsg)
	s.Len(subscribers, 1)

	subscribers = subscriptionManager.GetSubscribers("2", comm2.CoordinatorPingMsg)
	s.Len(subscribers, 0)
}
