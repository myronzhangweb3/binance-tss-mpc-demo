package routers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"tss-demo/logging"
	"tss-demo/service"
)

type Server struct {
	engine *gin.Engine
}

func NewServer() *Server {
	engine := gin.New()

	engine.Use(gin.Recovery())

	return &Server{
		engine: engine,
	}
}

func (s *Server) InitTssDemoApiRouter() {

	v1 := s.engine.Group("api/v1")

	health := v1.Group("/")
	health.GET("", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{})
	})

	userInfo := v1.Group("/")

	userInfo.GET("genkey", func(ctx *gin.Context) {
		result, err := service.KeygenEventHandler.HandleEvents()
		if err != nil {
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": fmt.Sprintf("Failed executing keygen. error: %v", err),
			})
			return
		}

		ctx.JSON(200, gin.H{
			"code":    200,
			"result":  result,
			"message": "success",
		})
	})
	userInfo.POST("sign", func(ctx *gin.Context) {
		params := &SignRequest{}
		if err := ctx.ShouldBindBodyWithJSON(params); err != nil {
			msg := fmt.Sprintf("bind json error. error: %v", err)
			logging.Log.Error(msg)
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": msg,
			})
			return
		}
		result, err := service.SignEventHandler.HandleEvents(params.Address, params.Hash)
		if err != nil {
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": fmt.Sprintf("Failed executing sign. error: %v", err),
			})
			return
		}

		ctx.JSON(200, gin.H{
			"code":    200,
			"result":  result,
			"message": "success",
		})
	})
}

func (s *Server) Run(addr string) error {

	return s.engine.Run(addr)
}
