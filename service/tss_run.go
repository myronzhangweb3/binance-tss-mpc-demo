// The Licensed Work is (c) 2022 Sygma
// SPDX-License-Identifier: LGPL-3.0-only

package service

import (
	"context"
	"fmt"
	"github.com/sygmaprotocol/sygma-core/store"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"tss-demo/service/event_handlers"
	"tss-demo/tss_util/comm/elector"
	"tss-demo/tss_util/comm/p2p"
	"tss-demo/tss_util/health"
	"tss-demo/tss_util/jobs"
	"tss-demo/tss_util/keyshare"
	"tss-demo/tss_util/metrics"
	propStore "tss-demo/tss_util/store"
	"tss-demo/tss_util/topology"
	"tss-demo/tss_util/tss"
	"tss-demo/tss_util/tss_config"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sygmaprotocol/sygma-core/observability"
	"github.com/sygmaprotocol/sygma-core/store/lvldb"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

var (
	Version string

	Coordinator        *tss.Coordinator
	Blockstore         *store.BlockStore
	FrostKeyshareStore *keyshare.FrostKeyshareStore
	PropStore          *propStore.PropStore

	KeygenEventHandler *event_handlers.KeygenEventHandler
	SignEventHandler   *event_handlers.SignEventHandler
)

// Run TODO 这里有问题，启动失败
func Run() error {
	var err error

	configFlag := viper.GetString(tss_config.ConfigFlagName)
	configURL := viper.GetString("tss.config_url")

	var configuration *tss_config.Config
	if configURL != "" {
		configuration, err = tss_config.GetSharedConfigFromNetwork(configURL)
		panicOnError(err)
	}

	if strings.ToLower(configFlag) == "env" {
		configuration, err = tss_config.GetConfigFromENV(configuration)
		panicOnError(err)
	} else {
		configuration, err = tss_config.GetConfigFromFile(configFlag, configuration)
		panicOnError(err)
	}

	observability.ConfigureLogger(configuration.RelayerConfig.LogLevel, os.Stdout)

	log.Info().Msg("Successfully loaded configuration")

	topologyProvider, err := topology.NewNetworkTopologyProvider(configuration.RelayerConfig.MpcConfig.TopologyConfiguration, http.DefaultClient)
	panicOnError(err)
	topologyStore := topology.NewTopologyStore(configuration.RelayerConfig.MpcConfig.TopologyConfiguration.Path)
	networkTopology, err := topologyStore.Topology()
	// if topology is not already in file, read from provider
	if err != nil {
		networkTopology, err = topologyProvider.NetworkTopology("")
		panicOnError(err)

		err = topologyStore.StoreTopology(networkTopology)
		panicOnError(err)
	}
	log.Info().Msgf("Successfully loaded topology")

	privBytes, err := crypto.ConfigDecodeKey(configuration.RelayerConfig.MpcConfig.Key)
	panicOnError(err)

	priv, err := crypto.UnmarshalPrivateKey(privBytes)
	panicOnError(err)

	connectionGate := p2p.NewConnectionGate(networkTopology)
	host, err := p2p.NewHost(priv, networkTopology, connectionGate, configuration.RelayerConfig.MpcConfig.Port)
	panicOnError(err)
	log.Info().Str("peerID", host.ID().String()).Msg("Successfully created libp2p host")

	go health.StartHealthEndpoint(configuration.RelayerConfig.HealthPort)

	communication := p2p.NewCommunication(host, "p2p/sygma")
	electorFactory := elector.NewCoordinatorElectorFactory(host, configuration.RelayerConfig.BullyConfig)
	Coordinator = tss.NewCoordinator(host, communication, electorFactory)

	// this is temporary solution related to specifics of aws deployment
	// effectively it waits until old instance is killed
	var db *lvldb.LVLDB
	for {
		db, err = lvldb.NewLvlDB(viper.GetString(tss_config.BlockstoreFlagName))
		if err != nil {
			log.Error().Err(err).Msg("Unable to connect to blockstore file, retry in 10 seconds")
			time.Sleep(10 * time.Second)
		} else {
			log.Info().Msg("Successfully connected to blockstore file")
			break
		}
	}
	Blockstore = store.NewBlockStore(db)
	keyshareStore := keyshare.NewECDSAKeyshareStore(configuration.RelayerConfig.MpcConfig.KeysharePath)
	FrostKeyshareStore = keyshare.NewFrostKeyshareStore(configuration.RelayerConfig.MpcConfig.FrostKeysharePath)
	PropStore = propStore.NewPropStore(db)

	// wait until executions are done and then stop further executions before exiting
	exitLock := &sync.RWMutex{}
	defer exitLock.Lock()

	mp, err := observability.InitMetricProvider(context.Background(), configuration.RelayerConfig.OpenTelemetryCollectorURL)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := mp.Shutdown(context.Background()); err != nil {
			log.Error().Msgf("Error shutting down meter provider: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sygmaMetrics, err := metrics.NewSygmaMetrics(ctx, mp.Meter("relayer-metric-provider"), configuration.RelayerConfig.Env, configuration.RelayerConfig.Id, Version)
	if err != nil {
		panic(err)
	}

	go jobs.StartCommunicationHealthCheckJob(host, configuration.RelayerConfig.MpcConfig.CommHealthCheckInterval, sygmaMetrics)

	l := log.With().Str("chain", fmt.Sprintf("%v", "name"))
	KeygenEventHandler = event_handlers.NewKeygenEventHandler(l, Coordinator, host, communication, keyshareStore, networkTopology.Threshold)
	SignEventHandler = event_handlers.NewSignEventHandler(l, Coordinator, host, communication, keyshareStore)

	sysErr := make(chan os.Signal, 1)
	signal.Notify(sysErr,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGHUP,
		syscall.SIGQUIT)

	relayerName := viper.GetString("name")
	log.Info().Msgf("Started relayer: %s with PID: %s. Version: v%s", relayerName, host.ID().Pretty(), Version)

	key, err := keyshareStore.GetKeyshare()
	if err != nil {
		log.Info().Msg("Relayer not part of MPC. Waiting for refresh event...")
	} else {
		log.Info().Msgf("MPC key address: %s", ethcrypto.PubkeyToAddress(*key.Key.ECDSAPub.ToBtcecPubKey().ToECDSA()))
	}

	sig := <-sysErr
	log.Info().Msgf("terminating got ` [%v] signal", sig)
	return nil

}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
