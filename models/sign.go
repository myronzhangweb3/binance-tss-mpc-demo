package models

type SignRequest struct {
	Hash string `json:"hash" binding:"required"`
}
