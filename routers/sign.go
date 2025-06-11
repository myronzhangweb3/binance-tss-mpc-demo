package routers

type SignRequest struct {
	Hash string `json:"hash" binding:"required"`
}
