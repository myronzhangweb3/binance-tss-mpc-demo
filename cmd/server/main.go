package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"tss-demo/logging"
	"tss-demo/routers"
	"tss-demo/service"

	_ "tss-demo/config"
)

func main() {
	logging.InitLoggerWithLogFile("tx_signer", "logs/tx_signer.log")

	var env = viper.GetString("ENV")
	if env != "production" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	go func() {
		err := service.Run()
		if err != nil {
			panic(err)
		}
	}()
	
	server := routers.NewServer()
	server.InitTssDemoApiRouter()

	addr := fmt.Sprintf(":%d", viper.GetInt("port"))
	logging.Log.Info(fmt.Sprintf("web listen: %s", addr))
	go func() {
		if err := server.Run(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("listen error: %v\n", err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logging.Log.Info("Server exiting")
}
