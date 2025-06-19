package keygen

// Request request to do keygen
type Request struct {
	Keys       []string `json:"keys"`
	LeaderSalt int64    `json:"leader_salt"`
	Version    string   `json:"tss_version"`
}

// NewRequest creeate a new instance of keygen.Request
func NewRequest(keys []string, blockHeight int64, version string) Request {
	return Request{
		Keys:       keys,
		LeaderSalt: blockHeight,
		Version:    version,
	}
}
