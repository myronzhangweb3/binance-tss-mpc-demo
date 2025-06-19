package keymanager

import (
	"encoding/hex"
	"fmt"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	"binance-tss-mpc-server/pkg/chainclients/xrp/keymanager/secp256k1"
)

type KeyManager struct {
	AccountID    string // base58 encoded address with 'r' prefix and checksum
	PublicKey    string // base58 encoded w/ prefix and checksum
	PublicKeyHex string // raw hex encoded pub key
	KeyType      CryptoAlgorithm
	Keys         Keys
}

func NewKeyManager(key cryptotypes.PrivKey, keyType CryptoAlgorithm) (*KeyManager, error) {
	var keys Keys
	var err error
	switch keyType {
	case ED25519:
		return nil, fmt.Errorf("ed25519 is not currently supported")
	case SECP256K1:
		keys, err = secp256k1.DeriveKeysFromMasterPrivateKey(key.Bytes())
		if err != nil {
			return nil, fmt.Errorf("fail generate xrp wallet from secp256k1 seed: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	return &KeyManager{
		AccountID:    MasterPubKeyToAccountID(keys.GetFormattedPublicKey()),
		KeyType:      keyType,
		PublicKey:    EncodePublicKey(keys.GetFormattedPublicKey()),
		PublicKeyHex: hex.EncodeToString(keys.GetFormattedPublicKey()),
		Keys:         keys,
	}, nil
}

func (m *KeyManager) Pubkey() string {
	return m.PublicKey
}

func (m *KeyManager) Sign(msg []byte) ([]byte, error) {
	return m.Keys.Sign(msg)
}

// Get formatted address, passing in a prefix.
func (w *KeyManager) GetAddr() string {
	return w.AccountID
}

type Keys interface {
	GetFormattedPublicKey() []byte
	Sign(message []byte) ([]byte, error)
	Verify(message, signature []byte) (bool, error)
}

// Algorithm represents supported cryptographic algorithms.
//
//go:generate stringer -type=CryptoAlgorithm
type CryptoAlgorithm int

const (
	// SECP256K1 represents the secp256k1 elliptic curve algorithm.
	SECP256K1 CryptoAlgorithm = iota
	// ED25519 represents the Ed25519 elliptic curve algorithm.
	ED25519
)
