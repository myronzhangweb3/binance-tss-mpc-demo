package test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
)

func sign(chainID *big.Int, encodedTx []byte, sig []byte) (string, error) {
	tx, err := decodeRlp(encodedTx)
	if err != nil {
		return "", err
	}
	var s types.Signer
	switch tx.Type() {
	case types.LegacyTxType:
		s = types.NewEIP155Signer(chainID)
	case types.DynamicFeeTxType:
		s = types.NewLondonSigner(chainID)
	default:
		return "", errors.New("transaction type wallet not supported")
	}
	signedTx, err := tx.WithSignature(s, sig)
	if err != nil {
		return "", fmt.Errorf("error signing transaction: %s", err)
	}
	data, err := signedTx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("error encoding signed transaction: %s", err)
	}

	return fmt.Sprintf("0x%s", hex.EncodeToString(data)), nil
}

func buildRlp() (*big.Int, string, error) {
	fromAddress := common.HexToAddress("0x9591bB8DaBe3291377f2dd4C5F3fe71fDe58957B")
	toAddress := common.HexToAddress("0x9591bB8DaBe3291377f2dd4C5F3fe71fDe58957B")

	// build tx
	client, err := rpc.DialContext(context.Background(), "https://eth-sepolia.public.blastapi.io")
	if err != nil {
		return nil, "", err
	}
	ethClient := ethclient.NewClient(client)
	nonce, err := ethClient.NonceAt(context.Background(), fromAddress, nil)
	if err != nil {
		return nil, "", err
	}
	gasPrice, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, "", err
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(2))
	gasLimit := uint64(21000)
	value := big.NewInt(0)
	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		return nil, "", err
	}
	var data []byte
	tx := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        &toAddress,
		Value:     value,
		Gas:       gasLimit,
		GasFeeCap: gasPrice,
		GasTipCap: gasPrice,
		Data:      data,
	}
	encodedTx, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return nil, "", err
	}

	return chainID, hex.EncodeToString(encodedTx), nil
}

func decodeRlp(encodedTx []byte) (*types.Transaction, error) {
	legacyTx := new(types.LegacyTx)
	errDecodeLegacyTx := rlp.DecodeBytes(encodedTx, legacyTx)
	if errDecodeLegacyTx != nil {
		dynamicFeeTx := new(types.DynamicFeeTx)
		errDecodeDynamicFeeTx := rlp.DecodeBytes(encodedTx, dynamicFeeTx)
		if errDecodeDynamicFeeTx != nil {
			return types.NewTx(dynamicFeeTx), errors.New("error decoding transaction")
		}
		return types.NewTx(dynamicFeeTx), nil
	}
	return types.NewTx(legacyTx), nil
}
