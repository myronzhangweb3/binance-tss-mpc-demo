package config

import (
	"fmt"

	"github.com/spf13/viper"
)

func init() {
	// Read in from .env file if available
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Load Config warning: %s\n", err)
	}

	// Read in from environment variables
	// common
	_ = viper.BindEnv("LOG.LEVEL")

	_ = viper.BindEnv("ENV")

	_ = viper.BindEnv("PORT")

	_ = viper.BindEnv("TSS_CONFIG")
	_ = viper.BindEnv("NAME")
	_ = viper.BindEnv("BLOCKSTORE")

}
