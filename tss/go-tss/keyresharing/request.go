package keyresharing

type Request struct {
	PoolPubKey string   `json:"pool_pub_key"`
	Keys       []string `json:"keys"`
	LeaderSalt int64    `json:"leader_salt"`
	Version    string   `json:"tss_version"`
}

func NewRequest(address string, blockHeight int64, version string) Request {
	return Request{
		PoolPubKey: address,
		LeaderSalt: blockHeight,
		Version:    version,
	}
}
