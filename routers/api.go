package routers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"tss-demo/logging"
	"tss-demo/models"
)

type Server struct {
	engine *gin.Engine
}

func NewServer() *Server {
	engine := gin.New()

	engine.Use(gin.Recovery())
	engine.Use(CORSMiddleware())

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

	userInfo.POST("genkey", func(ctx *gin.Context) {
		params := &models.GenerateAddress{}
		if err := ctx.ShouldBindBodyWithJSON(params); err != nil {
			msg := fmt.Sprintf("bind json error. error: %v", err)
			logging.Log.Error(msg)
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": msg,
			})
			return
		}
		ctx.JSON(200, gin.H{
			"code":    200,
			"result":  "result",
			"message": "success",
		})
	})
	userInfo.POST("sign", func(ctx *gin.Context) {
		params := &models.SignRequest{}
		if err := ctx.ShouldBindBodyWithJSON(params); err != nil {
			msg := fmt.Sprintf("bind json error. error: %v", err)
			logging.Log.Error(msg)
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": msg,
			})
			return
		}
		ctx.JSON(200, gin.H{
			"code":    200,
			"result":  "result",
			"message": "success",
		})
	})
}

func (s *Server) Run(addr string) error {

	return s.engine.Run(addr)
}
