package keysign

import (
	"binance-tss-mpc-server/tss/go-tss/blame"
	"binance-tss-mpc-server/tss/go-tss/common"
)

// signature
type Signature struct {
	Msg        string `json:"signed_msg"`
	Sign       string `json:"sign"`
	R          string `json:"r"`
	S          string `json:"s"`
	RecoveryID string `json:"recovery_id"`
}

// Response key sign response
type Response struct {
	Signatures []Signature   `json:"signatures"`
	Status     common.Status `json:"status"`
	Blame      blame.Blame   `json:"blame"`
}

func NewSignature(msg, sign, r, s, recoveryID string) Signature {
	return Signature{
		Msg:        msg,
		Sign:       sign,
		R:          r,
		S:          s,
		RecoveryID: recoveryID,
	}
}

func NewResponse(signatures []Signature, status common.Status, blame blame.Blame) Response {
	return Response{
		Signatures: signatures,
		Status:     status,
		Blame:      blame,
	}
}
