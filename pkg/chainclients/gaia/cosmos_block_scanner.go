package gaia

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	sdkmath "cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	ctypes "github.com/cosmos/cosmos-sdk/types"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"

	upgradetypes "cosmossdk.io/x/upgrade/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	authvesting "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	distribtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	govv1types "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	govv1beta1types "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	paramsproptypes "github.com/cosmos/cosmos-sdk/x/params/types/proposal"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/cometbft/cometbft/crypto/tmhash"
	rpcclienthttp "github.com/cometbft/cometbft/rpc/client/http"
	tmtypes "github.com/cometbft/cometbft/types"

	"binance-tss-mpc-server/blockscanner"
	"binance-tss-mpc-server/common"
	"binance-tss-mpc-server/common/cosmos"
	"binance-tss-mpc-server/config"
	"binance-tss-mpc-server/metrics"
	"binance-tss-mpc-server/thorclient"
	"binance-tss-mpc-server/thorclient/types"
)

// SolvencyReporter is to report solvency info to THORNode
type SolvencyReporter func(int64) error

const (
	// GasUpdatePeriodBlocks is the block interval at which we report gas fee changes.
	GasUpdatePeriodBlocks = 10

	// GasPriceFactor is a multiplier applied to the gas amount before dividing by the gas
	// limit to determine the gas price, and later used as a divisor on the final fee -
	// this avoid the integer division going to zero, and can be thought of as the
	// reciprocal of the gas price precision.
	GasPriceFactor = uint64(1e9)

	// GasLimit is the default gas limit we will use for all outbound transactions.
	GasLimit = 200000

	// GasCacheTransactions is the number of transactions over which we compute an average
	// (mean) gas price to use for outbound transactions. Note that only transactions
	// using the chain fee asset will be considered.
	GasCacheTransactions = 100
)

var (
	ErrInvalidScanStorage = errors.New("scan storage is empty or nil")
	ErrInvalidMetrics     = errors.New("metrics is empty or nil")
	ErrEmptyTx            = errors.New("empty tx")
)

// CosmosBlockScanner is to scan the blocks
type CosmosBlockScanner struct {
	cfg                   config.BifrostBlockScannerConfiguration
	logger                zerolog.Logger
	db                    blockscanner.ScannerStorage
	cdc                   *codec.ProtoCodec
	txConfig              client.TxConfig
	rpc                   TendermintRPC
	bridge                thorclient.ThorchainBridge
	solvencyReporter      SolvencyReporter
	globalNetworkFeeQueue chan common.NetworkFee

	// feeCache contains a rolling window of suggested gas fees which are computed as the
	// gas price paid in each observed transaction multiplied by the default GasLimit.
	// Fees are stored at 100x the values on the observed chain due to compensate for the
	// difference in base chain decimals (thorchain:1e8, gaia:1e6).
	feeCache []sdkmath.Uint
	lastFee  sdkmath.Uint
}

// NewCosmosBlockScanner create a new instance of BlockScan
func NewCosmosBlockScanner(rpcHost string,
	cfg config.BifrostBlockScannerConfiguration,
	scanStorage blockscanner.ScannerStorage,
	bridge thorclient.ThorchainBridge,
	m *metrics.Metrics,
	solvencyReporter SolvencyReporter,
) (*CosmosBlockScanner, error) {
	if scanStorage == nil {
		return nil, errors.New("scanStorage is nil")
	}
	if m == nil {
		return nil, errors.New("metrics is nil")
	}

	logger := log.Logger.With().Str("module", "blockscanner").Str("chain", cfg.ChainID.String()).Logger()

	// Bifrost only supports an "RPCHost" in its configuration.
	// We also need to access GRPC for Cosmos chains

	// Registry for decoding gaia txs
	// Note: we register gaia's cosmos sdk types
	// don't use thorchain's codec as it is a smaller subset of codecs
	registry := codectypes.NewInterfaceRegistry()
	authtypes.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	authvesting.RegisterInterfaces(registry)
	stakingtypes.RegisterInterfaces(registry)
	cryptocodec.RegisterInterfaces(registry)
	govv1types.RegisterInterfaces(registry)
	govv1beta1types.RegisterInterfaces(registry)
	paramsproptypes.RegisterInterfaces(registry)
	upgradetypes.RegisterInterfaces(registry)
	distribtypes.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)

	// Registry for encoding txs
	txConfig := tx.NewTxConfig(cdc, []signingtypes.SignMode{signingtypes.SignMode_SIGN_MODE_DIRECT})
	rpcClient, err := rpcclienthttp.New(rpcHost, "/websocket")
	if err != nil {
		logger.Fatal().Err(err).Msg("fail to create tendemrint rpcclient")
	}

	return &CosmosBlockScanner{
		cfg:              cfg,
		logger:           logger,
		db:               scanStorage,
		cdc:              cdc,
		txConfig:         txConfig,
		rpc:              rpcClient,
		feeCache:         make([]sdkmath.Uint, 0),
		lastFee:          sdkmath.NewUint(0),
		bridge:           bridge,
		solvencyReporter: solvencyReporter,
	}, nil
}

// GetHeight returns the height from the latest block minus 1
// NOTE: we must lag by one block due to a race condition fetching the block results
// Since the GetLatestBlockRequests tells what transactions will be in the block at T+1
func (c *CosmosBlockScanner) GetHeight() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resultBlock, err := c.rpc.Block(ctx, nil)
	if err != nil {
		return 0, err
	}

	return resultBlock.Block.Header.Height - 1, nil
}

// GetNetworkFee returns current chain network fee according to Bifrost.
func (c *CosmosBlockScanner) GetNetworkFee() (transactionSize, transactionFeeRate uint64) {
	return 1, c.lastFee.Uint64()
}

// FetchMemPool returns nothing since we are only concerned about finalized transactions in Cosmos
func (c *CosmosBlockScanner) FetchMemPool(height int64) (types.TxIn, error) {
	return types.TxIn{}, nil
}

// GetBlock returns a Tendermint block as a reference to a ResultBlock for a
// given height. As noted above, this is not necessarily the final state of transactions
// and must be checked again for success by getting the BlockResults in FetchTxs
func (c *CosmosBlockScanner) GetBlock(height int64) (*tmtypes.Block, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resultBlock, err := c.rpc.Block(ctx, &height)
	if err != nil {
		c.logger.Error().Int64("height", height).Msgf("failed to get block: %v", err)
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	return resultBlock.Block, nil
}

func (c *CosmosBlockScanner) updateGasCache(tx ctypes.FeeTx) {
	fees := tx.GetFee()

	// only consider transactions that have a single fee
	if len(fees) != 1 {
		return
	}

	// only consider transactions with fee paid in uatom
	coin, err := c.fromCosmosToThorchain(fees[0])
	if err != nil || !coin.Asset.Equals(c.cfg.ChainID.GetGasAsset()) {
		return
	}

	// sanity check to ensure fee is non-zero
	err = coin.Valid()
	if err != nil {
		c.logger.Err(err).Interface("fees", fees).Msg("transaction with zero fee")
		return
	}

	if tx.GetGas() == 0 {
		c.logger.Err(err).Interface("tx", tx).Msg("transaction with zero gas")
		return
	}

	// TODO: This conversion could be broken into a separate function for additional testing.
	// add the fee to our cache
	amount := coin.Amount.Mul(sdkmath.NewUint(GasPriceFactor)) // multiply to handle price < 1
	price := amount.Quo(sdkmath.NewUint(tx.GetGas()))          // divide by gas to get the price
	fee := price.Mul(sdkmath.NewUint(GasLimit))                // tx fee for default gas limit
	fee = fee.Quo(sdkmath.NewUint(GasPriceFactor))             // unroll the multiple
	c.feeCache = append(c.feeCache, fee)

	// truncate gas prices older than our max cached transactions
	if len(c.feeCache) > GasCacheTransactions {
		c.feeCache = c.feeCache[(len(c.feeCache) - GasCacheTransactions):]
	}
}

func (c *CosmosBlockScanner) averageFee() sdkmath.Uint {
	// avoid divide by zero
	if len(c.feeCache) == 0 {
		return sdkmath.NewUint(0)
	}

	// compute mean
	sum := sdkmath.NewUint(0)
	for _, val := range c.feeCache {
		sum = sum.Add(val)
	}
	mean := sum.Quo(sdkmath.NewUint(uint64(len(c.feeCache))))

	// round the price up to avoid fee noise
	resolution := sdkmath.NewUint(uint64(c.cfg.GasPriceResolution))
	if mean.LTE(resolution) {
		return resolution
	}
	mean = mean.Sub(sdkmath.NewUint(1))
	mean = mean.Quo(resolution)
	mean = mean.Add(sdkmath.NewUint(1))
	mean = mean.Mul(resolution)

	return mean
}

func (c *CosmosBlockScanner) updateGasFees(height int64) error {
	// post the gas fee over every cache period when we have a full gas cache
	if height%GasUpdatePeriodBlocks == 0 && len(c.feeCache) == GasCacheTransactions {
		gasFee := c.averageFee()

		// sanity check the fee is not zero
		if gasFee.IsZero() {
			return errors.New("suggested gas fee was zero")
		}

		// skip fee if less than 1 resolution away from the last
		feeDelta := sdkmath.MaxUint(c.lastFee, gasFee).Sub(sdkmath.MinUint(c.lastFee, gasFee))
		if feeDelta.LTE(sdkmath.NewUint(uint64(c.cfg.GasPriceResolution))) {
			return nil
		}

		// NOTE: We post the fee to the network instead of the transaction rate, and set the
		// transaction size 1 to ensure the MaxGas in the generated TxOut contains the
		// correct fee. We cannot pass the proper size and rate without a deeper change to
		// Thornode, as the rate on Cosmos chains is less than 1 and cannot be represented
		// by the uint.
		c.globalNetworkFeeQueue <- common.NetworkFee{
			Chain:           c.cfg.ChainID,
			Height:          height,
			TransactionSize: 1,
			TransactionRate: gasFee.Uint64(),
		}
		c.lastFee = gasFee
		c.logger.Info().
			Uint64("fee", gasFee.Uint64()).
			Int64("height", height).
			Msg("sent network fee to THORChain")
	}

	return nil
}

func (c *CosmosBlockScanner) processTxs(height int64, rawTxs []tmtypes.Tx) ([]*types.TxInItem, error) {
	// Proto types for Cosmos chains that we are transacting with may not be included in this repo.
	// Therefore, it is necessary to include them in the "proto" directory and register them in
	// the cdc (codec) that is passed below. Registry occurs in the NewCosmosBlockScanner function.
	decoder := tx.DefaultTxDecoder(c.cdc)

	// Fetch the block results so that we can ensure the transaction was successful before processing a TxInItem
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	blockResults, err := c.rpc.BlockResults(ctx, &height)
	if err != nil {
		return nil, fmt.Errorf("unable to get BlockResults: %w", err)
	}

	var txIn []*types.TxInItem
	for i, rawTx := range rawTxs {
		hash := hex.EncodeToString(tmhash.Sum(rawTx))
		var tx ctypes.Tx
		tx, err = decoder(rawTx)
		if err != nil {
			if strings.Contains(err.Error(), "unable to resolve type URL") {
				// One of the transaction message contains an unknown type. Although the
				// transaction may contain a valid MsgSend, we support transactions containing
				// only MsgSend and MsgExecuteContract. If the transaction contains MsgSend or
				// MsgExecuteContract log the error for debugging.
				if strings.Contains(err.Error(), "MsgSend") || strings.Contains(err.Error(), "MsgExecuteContract") {
					c.logger.Error().Str("tx", string(rawTx)).Err(err).Msg("unable to decode msg")
				}
			}
			continue
		}

		feeTx, _ := tx.(ctypes.FeeTx)
		fees := feeTx.GetFee()
		mem, _ := tx.(ctypes.TxWithMemo)
		memo := mem.GetMemo()
		c.updateGasCache(feeTx)

		for _, msg := range tx.GetMsgs() {
			if msg, isMsgSend := msg.(*banktypes.MsgSend); isMsgSend {
				// Transaction contains a relevant MsgSend, check if the transaction was successful...
				if blockResults.TxsResults[i].Code != 0 {
					c.logger.Warn().Str("txhash", hash).Int64("height", height).Msg("inbound tx has non-zero response code, ignoring...")
					continue
				}

				// Convert cosmos coins to thorchain coins (taking into account asset decimal precision)
				coins := common.Coins{}
				for _, coin := range msg.Amount {
					var cCoin common.Coin
					cCoin, err = c.fromCosmosToThorchain(coin)
					if err != nil {
						c.logger.Debug().Err(err).Interface("coins", c).Msg("unable to convert coin, not whitelisted. skipping...")
						continue
					}
					coins = append(coins, cCoin)
				}

				// Ignore the tx when no coins exist
				if coins.IsEmpty() {
					continue
				}

				// Convert cosmos gas to thorchain coins (taking into account gas asset decimal precision)
				gasFees := common.Gas{}
				for _, fee := range fees {
					var cCoin common.Coin
					cCoin, err = c.fromCosmosToThorchain(fee)
					if err != nil {
						c.logger.Debug().Err(err).Interface("fees", fees).Msg("unable to convert coin, not whitelisted. skipping...")
						continue
					}
					gasFees = append(gasFees, cCoin)
				}
				// THORChain only supports gas paid in ATOM, if gas is paid in another asset
				// then fake gas as `0.000001 ATOM`, the fee is not used but cannot be empty
				if gasFees.IsEmpty() {
					gasFees = append(gasFees, common.NewCoin(c.cfg.ChainID.GetGasAsset(), cosmos.NewUint(1)))
				}
				txIn = append(txIn, &types.TxInItem{
					Tx:          hash,
					BlockHeight: height,
					Memo:        memo,
					Sender:      msg.FromAddress,
					To:          msg.ToAddress,
					Coins:       coins,
					Gas:         gasFees,
				})

				// If there are more than one TxIn item per transaction hash,
				// thornode will fail to process any after the first.
				// Therefore, limit to 1 MsgSend per transaction.
				break
			}
		}

	}

	return txIn, nil
}

func (c *CosmosBlockScanner) FetchTxs(height, chainHeight int64) (types.TxIn, error) {
	block, err := c.GetBlock(height)
	if err != nil {
		return types.TxIn{}, err
	}

	txs, err := c.processTxs(height, block.Data.Txs)
	if err != nil {
		return types.TxIn{}, err
	}

	txIn := types.TxIn{
		Chain:    c.cfg.ChainID,
		TxArray:  txs,
		Filtered: false,
		MemPool:  false,
	}

	// skip reporting network fee and solvency if block more than flexibility blocks from tip
	if chainHeight-height > c.cfg.ObservationFlexibilityBlocks {
		return txIn, nil
	}

	err = c.updateGasFees(height)
	if err != nil {
		c.logger.Err(err).Int64("height", height).Msg("unable to update network fee")
	}

	if err = c.solvencyReporter(height); err != nil {
		c.logger.Err(err).Msg("fail to send solvency to THORChain")
	}

	return txIn, nil
}
