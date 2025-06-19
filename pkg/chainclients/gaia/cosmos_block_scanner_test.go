package gaia

import (
	"fmt"

	sdkmath "cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	cKeys "github.com/cosmos/cosmos-sdk/crypto/keyring"
	ctypes "github.com/cosmos/cosmos-sdk/types"
	btypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	protov2 "google.golang.org/protobuf/proto"

	"binance-tss-mpc-server/common"
	"binance-tss-mpc-server/config"
	"binance-tss-mpc-server/metrics"
	"binance-tss-mpc-server/thorclient"
	"github.com/rs/zerolog/log"

	"binance-tss-mpc-server/cmd"
	. "gopkg.in/check.v1"
)

// -------------------------------------------------------------------------------------
// Mock FeeTx
// -------------------------------------------------------------------------------------

var _ ctypes.FeeTx = &MockFeeTx{}

type MockFeeTx struct {
	fee ctypes.Coins
	gas uint64
}

func (m *MockFeeTx) GetMsgs() []ctypes.Msg {
	return nil
}

func (m *MockFeeTx) GetMsgsV2() ([]protov2.Message, error) {
	return nil, nil
}

func (m *MockFeeTx) ValidateBasic() error {
	return nil
}

func (m *MockFeeTx) GetGas() uint64 {
	return m.gas
}

func (m *MockFeeTx) GetFee() ctypes.Coins {
	return m.fee
}

func (m *MockFeeTx) FeePayer() []byte {
	return nil
}

func (m *MockFeeTx) FeeGranter() []byte {
	return nil
}

// -------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------

type BlockScannerTestSuite struct {
	m      *metrics.Metrics
	bridge thorclient.ThorchainBridge
	keys   *thorclient.Keys
}

var _ = Suite(&BlockScannerTestSuite{})

func (s *BlockScannerTestSuite) SetUpSuite(c *C) {
	s.m = GetMetricForTest(c)
	c.Assert(s.m, NotNil)
	cfg := config.BifrostClientConfiguration{
		ChainID:         "thorchain",
		ChainHost:       "localhost",
		SignerName:      "bob",
		SignerPasswd:    "password",
		ChainHomeFolder: "",
	}

	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	kb := cKeys.NewInMemory(cdc)
	_, _, err := kb.NewMnemonic(cfg.SignerName, cKeys.English, cmd.THORChainHDPath, cfg.SignerPasswd, hd.Secp256k1)
	c.Assert(err, IsNil)
	thorKeys := thorclient.NewKeysWithKeybase(kb, cfg.SignerName, cfg.SignerPasswd)
	c.Assert(err, IsNil)
	s.bridge, err = thorclient.NewThorchainBridge(cfg, s.m, thorKeys)
	c.Assert(err, IsNil)
	s.keys = thorKeys
}

func (s *BlockScannerTestSuite) TestCalculateAverageGasFees(c *C) {
	cfg := config.BifrostBlockScannerConfiguration{
		ChainID:            common.GAIAChain,
		GasPriceResolution: 100_000,
		WhitelistCosmosAssets: []config.WhitelistCosmosAsset{
			{Denom: "uatom", Decimals: 6, THORChainSymbol: "ATOM"},
		},
	}
	blockScanner := CosmosBlockScanner{cfg: cfg}

	atomToThorchain := int64(100)

	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit / 2,
		fee: ctypes.Coins{ctypes.NewCoin("uatom", sdkmath.NewInt(10000))},
	})
	c.Check(len(blockScanner.feeCache), Equals, 1)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(20000*atomToThorchain)))

	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit / 2,
		fee: ctypes.Coins{ctypes.NewCoin("uatom", sdkmath.NewInt(10000))},
	})
	c.Check(len(blockScanner.feeCache), Equals, 2)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(20000*atomToThorchain)))

	// two blocks at half fee should average to 75% of last
	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit,
		fee: ctypes.Coins{ctypes.NewCoin("uatom", sdkmath.NewInt(10000))},
	})
	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit,
		fee: ctypes.Coins{ctypes.NewCoin("uatom", sdkmath.NewInt(10000))},
	})
	c.Check(len(blockScanner.feeCache), Equals, 4)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(15000*atomToThorchain)))

	// skip transactions with multiple coins
	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit,
		fee: ctypes.Coins{
			ctypes.NewCoin("uatom", sdkmath.NewInt(10000)),
			ctypes.NewCoin("uusd", sdkmath.NewInt(10000)),
		},
	})
	c.Check(len(blockScanner.feeCache), Equals, 4)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(15000*atomToThorchain)))

	// skip transactions with fees not in uatom
	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit,
		fee: ctypes.Coins{
			ctypes.NewCoin("uusd", sdkmath.NewInt(10000)),
		},
	})
	c.Check(len(blockScanner.feeCache), Equals, 4)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(15000*atomToThorchain)))

	// skip transactions with zero fee
	blockScanner.updateGasCache(&MockFeeTx{
		gas: GasLimit,
		fee: ctypes.Coins{
			ctypes.NewCoin("uusd", sdkmath.NewInt(0)),
		},
	})
	c.Check(len(blockScanner.feeCache), Equals, 4)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(15000*atomToThorchain)))

	// ensure we only cache the transaction limit number of blocks
	for i := 0; i < GasCacheTransactions; i++ {
		blockScanner.updateGasCache(&MockFeeTx{
			gas: GasLimit,
			fee: ctypes.Coins{
				ctypes.NewCoin("uatom", sdkmath.NewInt(10000)),
			},
		})
	}
	c.Check(len(blockScanner.feeCache), Equals, GasCacheTransactions)
	c.Check(blockScanner.averageFee().String(), Equals, fmt.Sprintf("%d", uint64(10000*atomToThorchain)))
}

func (s *BlockScannerTestSuite) TestGetBlock(c *C) {
	cfg := config.BifrostBlockScannerConfiguration{ChainID: common.GAIAChain}
	blockScanner := CosmosBlockScanner{
		cfg: cfg,
		rpc: &mockTendermintRPC{},
	}

	block, err := blockScanner.GetBlock(1)

	c.Assert(err, IsNil)
	c.Assert(len(block.Data.Txs), Equals, 1)
	c.Assert(block.Header.Height, Equals, int64(6509672))
}

func (s *BlockScannerTestSuite) TestProcessTxs(c *C) {
	cfg := config.BifrostBlockScannerConfiguration{
		ChainID: common.GAIAChain,
		WhitelistCosmosAssets: []config.WhitelistCosmosAsset{
			{Denom: "uatom", Decimals: 6, THORChainSymbol: "ATOM"},
		},
	}
	registry := s.bridge.GetContext().InterfaceRegistry
	btypes.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)

	blockScanner := CosmosBlockScanner{
		cfg:    cfg,
		rpc:    &mockTendermintRPC{},
		cdc:    cdc,
		logger: log.Logger.With().Str("module", "blockscanner").Str("chain", common.GAIAChain.String()).Logger(),
	}

	block, err := blockScanner.GetBlock(1)
	c.Assert(err, IsNil)

	txInItems, err := blockScanner.processTxs(1, block.Data.Txs)
	c.Assert(err, IsNil)

	// proccessTxs should filter out everything besides the valid MsgSend
	c.Assert(len(txInItems), Equals, 1)
}
