package mnemonic

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ed25519"
)

type Account struct {
	PrivateKey string
	PublicKey  string
	Mnemonic   string
	Err        error
}

// GenerateMnemonicByLength generate mnemonic and then use mnemonic to generate the private key and its public key
func GenerateMnemonicByLength(length int) *Account {
	// Length of mnemonic must be in the key list in mneMap.If length is error，there will no mnemonic.
	mneMap := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}
	if _, ok := mneMap[length]; !ok {
		return &Account{
			PublicKey:  "",
			PrivateKey: "",
			Mnemonic:   "",
			Err:        fmt.Errorf("非法长度,长度必须为（其中一个）:12，15，18，21，24"),
		}
	}
	bitSize := mneMap[length]
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return &Account{
			PublicKey:  "",
			PrivateKey: "",
			Mnemonic:   "",
			Err:        fmt.Errorf("生成随机序列失败"),
		}
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return &Account{
			PublicKey:  "",
			PrivateKey: "",
			Mnemonic:   "",
			Err:        fmt.Errorf("助记词字典加载错误"),
		}
	}
	// Default that there is no password.
	seed := bip39.NewSeed(mnemonic, "")
	seedForMultiVAC := seed[:32]
	reader := bytes.NewReader(seedForMultiVAC)
	pub, prv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return &Account{
			PrivateKey: "",
			PublicKey:  "",
			Mnemonic:   "",
			Err:        fmt.Errorf("密钥生成失败，err:%v", err),
		}
	}
	return &Account{
		PrivateKey: hex.EncodeToString(prv),
		PublicKey:  hex.EncodeToString(pub),
		Mnemonic:   mnemonic,
		Err:        nil,
	}
}

// MnemonicToPrivateKey get private key and public key by using mnemonic.Returns publickey,privatekey,error
func MnemonicToPrivateKey(mnemonic string) (string, string, error) {
	seed := bip39.NewSeed(mnemonic, "")
	seedForMultiVAC := seed[:32]
	reader := bytes.NewReader(seedForMultiVAC)
	pub, prv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(prv), nil

}
