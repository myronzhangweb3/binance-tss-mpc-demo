package types

import (
	"binance-tss-mpc-server/common"
	cosmos "binance-tss-mpc-server/common/cosmos"
	. "gopkg.in/check.v1"
)

type TxOutTestSuite struct{}

var _ = Suite(&TxOutTestSuite{})

func (TxOutTestSuite) TestTxOutItemHash(c *C) {
	item := TxOutItem{
		Chain:       "ETH",
		ToAddress:   "0x90f2b1ae50e6018230e90a33f98c7844a0ab635a",
		VaultPubKey: "",
		Coins: common.Coins{
			common.NewCoin(common.ETHAsset, cosmos.NewUint(194765912)),
		},
		Memo:   "REFUND:9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
		InHash: "9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
	}
	c.Check(item.Hash(), Equals, "D3F7241B1D046E5D0AC236366069947D135840A998675FCC69FF4F26CEFB1B5C")

	item = TxOutItem{
		Chain:       "ETH",
		ToAddress:   "0x90f2b1ae50e6018230e90a33f98c7844a0ab635a",
		VaultPubKey: "",
		Memo:        "REFUND:9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
		InHash:      "9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
	}
	c.Check(item.Hash(), Equals, "F5FD1B7F57CB0CDFE5A39A896C8D7C8FA8B3C1C0177474E402990A0A3671FB0B")

	item = TxOutItem{
		Chain:       "ETH",
		ToAddress:   "0x90f2b1ae50e6018230e90a33f98c7844a0ab635a",
		VaultPubKey: "thorpub1addwnpepqv7kdf473gc4jyls7hlx4rg",
		Memo:        "REFUND:9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
		InHash:      "9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
	}
	c.Check(item.Hash(), Equals, "7947BD11B6ADC5861B6FFCFA4346786E7C708B1F1A67454F68403A3A647D506B")
}

func (TxOutTestSuite) TestTxOutItemEqualsShouldIgnoreHeight(c *C) {
	item1 := TxOutItem{
		Chain:       "ETH",
		ToAddress:   "0x90f2b1ae50e6018230e90a33f98c7844a0ab635a",
		VaultPubKey: "",
		Coins: common.Coins{
			common.NewCoin(common.ETHAsset, cosmos.NewUint(194765912)),
		},
		Memo:   "REFUND:9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
		InHash: "9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
	}
	item2 := TxOutItem{
		Chain:       "ETH",
		ToAddress:   "0x90f2b1ae50e6018230e90a33f98c7844a0ab635a",
		VaultPubKey: "",
		Coins: common.Coins{
			common.NewCoin(common.ETHAsset, cosmos.NewUint(194765912)),
		},
		Memo:   "REFUND:9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
		InHash: "9999A5A08D8FCF942E1AAAA01AB1E521B699BA3A009FA0591C011DC1FFDC5E68",
	}
	c.Check(item1.Equals(item2), Equals, true)

	item1.Height = 1
	item2.Height = 2
	c.Check(item1.Equals(item2), Equals, true)
}
