// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package p2p

import (
	"sync"
	comm2 "tss-demo/tss_util/comm"
)

// SessionSubscriptionManager manages channel subscriptions by comm.SessionID
type SessionSubscriptionManager struct {
	lock *sync.Mutex
	// sessionID -> messageType -> subscriptionID
	subscribersMap map[string]map[comm2.MessageType]map[string]chan *comm2.WrappedMessage
}

func NewSessionSubscriptionManager() SessionSubscriptionManager {
	return SessionSubscriptionManager{
		lock: &sync.Mutex{},
		subscribersMap: make(
			map[string]map[comm2.MessageType]map[string]chan *comm2.WrappedMessage,
		),
	}
}

func (ms *SessionSubscriptionManager) GetSubscribers(
	sessionID string,
	msgType comm2.MessageType,
) []chan *comm2.WrappedMessage {
	ms.lock.Lock()
	defer ms.lock.Unlock()
	subsAsMap, ok := ms.subscribersMap[sessionID][msgType]
	if !ok {
		return []chan *comm2.WrappedMessage{}
	}
	var subsAsArray []chan *comm2.WrappedMessage
	for _, sub := range subsAsMap {
		subsAsArray = append(subsAsArray, sub)
	}
	return subsAsArray
}

func (ms *SessionSubscriptionManager) SubscribeTo(
	sessionID string, msgType comm2.MessageType, channel chan *comm2.WrappedMessage,
) comm2.SubscriptionID {
	ms.lock.Lock()
	defer ms.lock.Unlock()

	_, ok := ms.subscribersMap[sessionID]
	if !ok {
		ms.subscribersMap[sessionID] =
			map[comm2.MessageType]map[string]chan *comm2.WrappedMessage{}
	}

	_, ok = ms.subscribersMap[sessionID][msgType]
	if !ok {
		ms.subscribersMap[sessionID][msgType] =
			map[string]chan *comm2.WrappedMessage{}
	}

	subID := comm2.NewSubscriptionID(sessionID, msgType)
	ms.subscribersMap[sessionID][msgType][subID.SubscriptionIdentifier()] = channel
	return subID
}

func (ms *SessionSubscriptionManager) UnSubscribeFrom(
	subscriptionID comm2.SubscriptionID,
) {
	ms.lock.Lock()
	defer ms.lock.Unlock()

	sessionID, msgType, subID, err := subscriptionID.Unwrap()
	if err != nil {
		return
	}

	_, ok := ms.subscribersMap[sessionID][msgType][subID]
	if !ok {
		return
	}

	delete(ms.subscribersMap[sessionID][msgType], subID)
}
