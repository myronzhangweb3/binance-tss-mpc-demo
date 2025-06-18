package routers

type SignRequest struct {
	Address string `json:"address" binding:"required"`
	Hash    string `json:"hash" binding:"required"`
}
