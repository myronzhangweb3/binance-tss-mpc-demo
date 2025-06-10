// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package topology

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"tss-demo/tss_util/tss_config/relayer"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rs/zerolog/log"
)

type NetworkTopology struct {
	Peers     []*peer.AddrInfo
	Threshold int
}

func (nt NetworkTopology) IsAllowedPeer(peer peer.ID) bool {
	for _, p := range nt.Peers {
		if p.ID == peer {
			return true
		}
	}

	return false
}

type RawTopology struct {
	Peers     []RawPeer `mapstructure:"Peers" json:"peers"`
	Threshold string    `mapstructure:"Threshold" json:"threshold"`
}

type RawPeer struct {
	PeerAddress string `mapstructure:"PeerAddress" json:"peerAddress"`
}
type Fetcher interface {
	Get(url string) (*http.Response, error)
}

type Decrypter interface {
	Decrypt(data []byte) []byte
}

type NetworkTopologyProvider interface {
	// NetworkTopology fetches latest topology from network and validates that
	// the version matches expected hash.
	NetworkTopology(hash string) (*NetworkTopology, error)
}

func NewNetworkTopologyProvider(config relayer.TopologyConfiguration, fetcher Fetcher) (NetworkTopologyProvider, error) {
	//decrypter, err := NewAESEncryption([]byte(config.EncryptionKey))
	//if err != nil {
	//	return nil, err
	//}

	return &TopologyProvider{
		//decrypter: decrypter,
		//url:       config.Url,
		fetcher: fetcher,
		path:    config.Path,
	}, nil
}

type TopologyProvider struct {
	//url string
	path string
	//decrypter Decrypter
	fetcher Fetcher
}

func (t *TopologyProvider) NetworkTopology(hash string) (*NetworkTopology, error) {
	log.Info().Msgf("Reading topology from path: %s", t.path)

	data, err := os.ReadFile(t.path)
	if err != nil {
		return nil, err
	}
	rawTopology := &RawTopology{}
	err = json.Unmarshal(data, rawTopology)
	if err != nil {
		return nil, err
	}

	return ProcessRawTopology(rawTopology)
}

func ProcessRawTopology(rawTopology *RawTopology) (*NetworkTopology, error) {
	var peers []*peer.AddrInfo
	for _, p := range rawTopology.Peers {
		addrInfo, err := peer.AddrInfoFromString(p.PeerAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid peer address %s: %w", p.PeerAddress, err)
		}
		peers = append(peers, addrInfo)
	}

	threshold, err := strconv.ParseInt(rawTopology.Threshold, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to parse mpc threshold from topology %v", err)
	}
	if threshold < 1 {
		return nil, fmt.Errorf("mpc threshold must be bigger then 0 %v", err)
	}
	return &NetworkTopology{Peers: peers, Threshold: int(threshold)}, nil
}
