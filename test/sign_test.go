package test

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"testing"
)

func TestGetRlp(t *testing.T) {
	chainID, encodedTxHex, err := buildRlp()
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
	fmt.Printf("Need sign hash: %s\n", h[2:])
}

func TestGetBroadcastTx(t *testing.T) {
	chainID, _, err := buildRlp()
	if err != nil {
		t.Fatal(err)
	}

	encodeTxHex := "eb83aa36a780835b4494835b4494825208949591bb8dabe3291377f2dd4c5f3fe71fde58957b8080c0808080"
	sig := "91e958618ef8f16ad26d59691fc31a8044b1c883cef44d143f5c468e97aaa26d2c8ecc4ec04981cc651fb8e821dd391d1f51248688cd70b24f689c0e1b502ca300"
	encodeTxHexBytes, err := hex.DecodeString(encodeTxHex)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	txHexStr, err := sign(chainID, encodeTxHexBytes, sigBytes)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("tx: %s\n", txHexStr)

	// tx: 0x02f86b83aa36a780835b4494835b4494825208949591bb8dabe3291377f2dd4c5f3fe71fde58957b8080c080a091e958618ef8f16ad26d59691fc31a8044b1c883cef44d143f5c468e97aaa26da02c8ecc4ec04981cc651fb8e821dd391d1f51248688cd70b24f689c0e1b502ca3
	// success tx: https://sepolia.etherscan.io/tx/0x0539b51e4f9fad12d440228b7d79ae21a645b8214f1286c156b6e88bdec257ab
}
