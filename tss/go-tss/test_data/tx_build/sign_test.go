package tx_build

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"log"
	"testing"
)

var (
	evmRpc     = "https://eth-sepolia.public.blastapi.io"
	mpcAddress = common.HexToAddress("0x8d3A0E56ac4C70e0d575e189af84C853a85ec5c7")
)

func TestGetRlp(t *testing.T) {
	chainID, encodedTxHex, err := buildRlp(evmRpc, mpcAddress, mpcAddress)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("EncodedTxHex: %s\n", encodedTxHex)

	encodedTxBytes, err := hex.DecodeString(encodedTxHex)
	tx, err := decodeRlp(encodedTxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var s types.Signer
	switch tx.Type() {
	case types.LegacyTxType:
		s = types.NewEIP155Signer(chainID)
	case types.DynamicFeeTxType:
		s = types.NewLondonSigner(chainID)
	default:
		t.Fatal(err)
	}
	h := s.Hash(tx)
	fmt.Printf("Need addSignToTx hash: %s\n", h.String()[2:])
}

func TestGetBroadcastTx(t *testing.T) {
	chainID, _, err := buildRlp(evmRpc, mpcAddress, mpcAddress)
	if err != nil {
		t.Fatal(err)
	}

	encodeTxHex := "eb83aa36a7808320abba8320abba825208948d3a0e56ac4c70e0d575e189af84c853a85ec5c78080c0808080"
	signHash := "db2ef62f99c4ca2be5618af6964f33d9b4e393df94283583095086f570950f58"
	rHex := "826288212d209ae44ca292edb705c4745384f9e9a0915fca586f911a2ecda942"
	sHex := "0d1b5ba6760c7cf1b3e7bdca8ae14b36886ac7750e4f548bb60132999212e3c1"
	recoveryIDHex := "01"

	sig, err := buildSignature(rHex, sHex, recoveryIDHex)
	if err != nil {
		t.Fatal(err)
	}
	signHashBytes, err := hex.DecodeString(signHash)
	if err != nil {
		t.Fatal(err)
	}
	encodeTxHexBytes, err := hex.DecodeString(encodeTxHex)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	txHexStr, err := addSignToTx(chainID, encodeTxHexBytes, sigBytes)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("tx: %s\n", txHexStr)

	pubKey, err := secp256k1.RecoverPubkey(signHashBytes, sigBytes)
	if err != nil {
		log.Fatalf("Failed to recover public key: %v", err)
	}
	pk, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		log.Fatalf("Failed to unmarshal public key: %v", err)
	}
	address := crypto.PubkeyToAddress(*pk)
	fmt.Printf("Recovered Ethereum Address: %s\n", address.Hex())

	// tx: 0x02f86b83aa36a780835b4494835b4494825208949591bb8dabe3291377f2dd4c5f3fe71fde58957b8080c080a091e958618ef8f16ad26d59691fc31a8044b1c883cef44d143f5c468e97aaa26da02c8ecc4ec04981cc651fb8e821dd391d1f51248688cd70b24f689c0e1b502ca3
	// success tx: https://sepolia.etherscan.io/tx/0x0539b51e4f9fad12d440228b7d79ae21a645b8214f1286c156b6e88bdec257ab
}

func buildSignature(rHex, sHex, recoveryIDHex string) (string, error) {
	r, err := hex.DecodeString(rHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode r: %v", err)
	}
	s, err := hex.DecodeString(sHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode s: %v", err)
	}

	// Convert recovery_id to v
	recoveryID, err := hex.DecodeString(recoveryIDHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode recovery_id: %v", err)
	}
	v := recoveryID[0]
	//v := recoveryID[0] + 27

	// Assemble signature
	signature := append(r, s...)
	signature = append(signature, v)

	return hex.EncodeToString(signature), nil
}
