package test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"net/http"
	"sync"
	"testing"
	"time"
)

var (
	evmRpc     = "https://eth-sepolia.public.blastapi.io"
	mpcAddress = common.HexToAddress("0x5d3Eab332f8cE8Ec0Bbc4DBDaA32A047896bFCBa")
)

func TestBuildSignTx(t *testing.T) {
	fmt.Printf("evmRpc: %s\n", evmRpc)
	fmt.Printf("mpcAddress: %s\n", mpcAddress)

	// build tx
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
	signHash := h.String()[2:]
	fmt.Printf("Need addSignToTx hash: %s\n", signHash)

	// sign tx
	jsonData := fmt.Sprintf(`{
		"pool_pub_key": "%s",
		"messages": ["%s"],
		"keys": [
			"thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
			"thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
			"thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
		],
		"tss_version": "0.14.0",
		"leader_salt": 1
	}`, mpcAddress, signHash)
	urls := []string{
		"http://127.0.0.1:8081/keysign",
		"http://127.0.0.1:8082/keysign",
		"http://127.0.0.1:8083/keysign",
	}

	startTime := time.Now()
	result := make(map[string]interface{})

	wg := sync.WaitGroup{}
	for i := range urls {
		wg.Add(1)
		go func() {
			response, err := sendRequest(urls[i], http.MethodPost, jsonData)
			if err != nil {
				wg.Done()
				t.Fatal(err)
			}
			fmt.Println(response)
			err = json.Unmarshal([]byte(response), &result)
			if err != nil {
				t.Fatal(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	elapsedTime := time.Since(startTime)
	fmt.Printf("Total time taken: %s\n", elapsedTime)

	// add sign to tx
	signatures := result["signatures"].([]interface{})[0].(map[string]interface{})
	rHex := signatures["r"].(string)
	sHex := signatures["s"].(string)
	recoveryIDHex := signatures["recovery_id"].(string)

	sig, err := buildSignature(rHex, sHex, recoveryIDHex)
	if err != nil {
		t.Fatal(err)
	}
	encodeTxHexBytes, err := hex.DecodeString(encodedTxHex)
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

}
