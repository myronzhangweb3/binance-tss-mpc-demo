package routers

import (
	"crypto/elliptic"
	"fmt"
	tsslibbig "github.com/binance-chain/tss-lib/common/int"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/ckd"
	"github.com/btcsuite/btcd/chaincfg"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"math/big"
	"tss-demo/logging"
	"tss-demo/service"
	"tss-demo/tss_util/keyshare"
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

	userInfo.GET("genkey/:sid", func(ctx *gin.Context) {
		sid := ctx.Param("sid")
		result, err := service.KeygenEventHandler.HandleEvents(sid)
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
	// TODO check
	userInfo.GET("deriving/:root/:path", func(ctx *gin.Context) {
		root := ctx.Param("root")
		path := ctx.Param("path")

		keyshareStore := keyshare.NewECDSAKeyshareStore(fmt.Sprintf("keyshare/key1-%s.keyshare", root))

		keys, err := keyshareStore.GetKeyshare()
		if err != nil {
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": fmt.Sprintf("Failed executing keygen. error: %v", err),
			})
			return
		}
		il, extendedChildPk, errorDerivation := derivingPubkeyFromPath(keys.Key.ECDSAPub, []byte(path), []uint32{12, 209, 3}, keys.Key.ECDSAPub.Curve())
		if errorDerivation != nil {
			ctx.JSON(200, gin.H{
				"code":    500,
				"message": fmt.Sprintf("Failed executing keygen. error: %v", errorDerivation),
			})
			return
		}
		address := ethcrypto.PubkeyToAddress(*extendedChildPk.PublicKey.ToECDSA())

		ctx.JSON(200, gin.H{
			"code": 200,
			"result": map[string]interface{}{
				"address": address,
				"il":      il,
			},
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

func derivingPubkeyFromPath(masterPub *crypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	pk := masterPub.ToBtcecPubKey()
	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}
	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, tsslibbig.Wrap(ec.Params().N), ec)
}
