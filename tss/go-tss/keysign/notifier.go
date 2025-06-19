package keysign

import (
	"errors"
	"fmt"
	"github.com/binance-chain/tss-lib/common"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Notifier is design to receive keysign signature, success or failure
type Notifier struct {
	MessageID  string
	messages   [][]byte // the message
	poolPubKey string
	resp       chan []*common.ECSignature
}

// NewNotifier create a new instance of Notifier
func NewNotifier(messageID string, messages [][]byte, poolPubKey string) (*Notifier, error) {
	if len(messageID) == 0 {
		return nil, errors.New("messageID is empty")
	}
	if len(messages) == 0 {
		return nil, errors.New("messages are nil")
	}
	if len(poolPubKey) == 0 {
		return nil, errors.New("pool pubkey is empty")
	}
	return &Notifier{
		MessageID:  messageID,
		messages:   messages,
		poolPubKey: poolPubKey,
		resp:       make(chan []*common.ECSignature, 1),
	}, nil
}

// verifySignature is a method to verify the signature against the message it signed , if the signature can be verified successfully
// There is a method call VerifyBytes in crypto.PubKey, but we can't use that method to verify the signature, because it always hash the message
// first and then verify the hash of the message against the signature , which is not the case in tss
// go-tss respect the payload it receives , assume the payload had been hashed already by whoever send it in.
func (n *Notifier) verifySignature(data *common.ECSignature, msg []byte) (bool, error) {
	pubKey, err := secp256k1.RecoverPubkey(msg, append(data.Signature, data.SignatureRecovery...))
	if err != nil {
		return false, fmt.Errorf("fail to recover public key:%w", err)
	}
	pk, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return false, fmt.Errorf("fail to unmarshal public key:%w", err)
	}
	return ethcommon.HexToAddress(n.poolPubKey) == crypto.PubkeyToAddress(*pk), nil
}

// ProcessSignature is to verify whether the signature is valid
// return value bool , true indicated we already gather all the signature from keysign party, and they are all match
// false means we are still waiting for more signature from keysign party
func (n *Notifier) ProcessSignature(data []*common.ECSignature) (bool, error) {
	// only need to verify the signature when data is not nil
	// when data is nil , which means keysign  failed, there is no signature to be verified in that case
	// for gg20, it wrap the signature R,S into ECSignature structure
	if len(data) != 0 {

		for i := 0; i < len(data); i++ {
			eachSig := data[i]
			msg := n.messages[i]
			if eachSig.GetSignature() != nil {
				verify, err := n.verifySignature(eachSig, msg)
				if err != nil || !verify {
					return false, fmt.Errorf("fail to verify signature: %w", err)
				}
			} else {
				return false, errors.New("keysign failed with nil signature")
			}
		}
		n.resp <- data
		return true, nil
	}
	return false, nil
}

// GetResponseChannel the final signature gathered from keysign party will be returned from the channel
func (n *Notifier) GetResponseChannel() <-chan []*common.ECSignature {
	return n.resp
}
