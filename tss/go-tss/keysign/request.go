package keysign

// Request request to sign a message
type Request struct {
	PoolPubKey    string   `json:"pool_pub_key"` // pub key of the pool that we would like to send this message from
	Messages      []string `json:"messages"`     // base64 encoded message to be signed
	SignerPubKeys []string `json:"signer_pub_keys"`
	LeaderSalt    int64    `json:"leader_salt"`
	Version       string   `json:"tss_version"`
}

func NewRequest(pk string, msgs []string, blockHeight int64, signers []string, version string) Request {
	return Request{
		PoolPubKey:    pk,
		Messages:      msgs,
		SignerPubKeys: signers,
		LeaderSalt:    blockHeight,
		Version:       version,
	}
}
