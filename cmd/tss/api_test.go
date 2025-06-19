package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func sendRequest(url, method, jsonData string) (string, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(jsonData)))
	if err != nil {
		return "", fmt.Errorf("fail to send post request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fail to send post request: %w", err)
	}
	defer resp.Body.Close()
	if status := resp.StatusCode; status != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: got %v want %v", status, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read response body: %v", err)
	}
	return string(body), nil
}

func TestP2pGen(t *testing.T) {
	response, err := sendRequest("http://127.0.0.1:8081/p2pgen", http.MethodGet, "")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(response)
}

func TestKeyGen(t *testing.T) {
	jsonData := `{
		"keys": [
			"thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
			"thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
			"thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
		],
		"tss_version": "0.14.0",
		"leader_salt": 1
	}`
	urls := []string{
		"http://127.0.0.1:8081/keygen",
		"http://127.0.0.1:8082/keygen",
		"http://127.0.0.1:8083/keygen",
	}

	startTime := time.Now() // 开始计时
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
			wg.Done()
		}()
	}
	wg.Wait()
	elapsedTime := time.Since(startTime)
	fmt.Printf("Total time taken: %s\n", elapsedTime)
}

func TestKeySign(t *testing.T) {
	jsonData := `{
		"pool_pub_key": "0x5d3Eab332f8cE8Ec0Bbc4DBDaA32A047896bFCBa",
		"messages": ["db2ef62f99c4ca2be5618af6964f33d9b4e393df94283583095086f570950f58"],
		"keys": [
			"thorpub1addwnpepq07lfyrczz5ltk2x9gdwp8lwuk4jqhfj0x9sllxr09zzqg0cf3dm78wtzae",
			"thorpub1addwnpepqw0t6d6waga7lh05dwa3st3fr7m3nmsmwpdsk7qzzcgr36ma4zsrvlg06u0",
			"thorpub1addwnpepq2cfzken8ynd2vuv4kaxzstyexd7sdvj5y7chhktdanety7prduasxq3caf"
		],
		"tss_version": "0.14.0",
		"leader_salt": 1
	}`
	urls := []string{
		"http://127.0.0.1:8081/keysign",
		"http://127.0.0.1:8082/keysign",
		"http://127.0.0.1:8083/keysign",
	}

	startTime := time.Now() // 开始计时
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
			wg.Done()
		}()
	}
	wg.Wait()
	elapsedTime := time.Since(startTime)
	fmt.Printf("Total time taken: %s\n", elapsedTime)
}

func TestKeyGenAndSign(t *testing.T) {
	TestKeyGen(t)
	TestKeySign(t)
}
