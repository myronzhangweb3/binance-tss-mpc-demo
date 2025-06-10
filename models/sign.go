package models

type SignRequestData struct {
	Sender    string `json:"sender" binding:"required"`
	ChainId   int    `json:"chain_id" binding:"required"`
	ChainType string `json:"chain_type" binding:"required"`
	Rlp       string `json:"rlp" binding:"required"`
	Key       string `json:"key" binding:"required"`
}

type SignRequest struct {
	Data      SignRequestData `json:"data" binding:"required"`
	Timestamp int64           `json:"timestamp" binding:"required"`
	Signature string          `json:"signature" binding:"required"`
}
