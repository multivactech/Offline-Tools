package mnemonic

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ed25519"
)

type Account struct {
	PrivateKey string
	PublicKey  string
	Mnemonic   string
	Err        error
}

// Generate mnemonic and then use mnemonic to generate the private key and its public key
func GenerateMnemonicByLength(length int) *Account {
	// Length of mnemonic must be in the key list in mneMap.
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
			Err:        errors.New("助记词长度不对"),
		}
	}
	bitSize := mneMap[length]
	entropy, _ := bip39.NewEntropy(bitSize)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, "")
	seedForMultiVAC := seed[:32]
	reader := bytes.NewReader(seedForMultiVAC)
	pub, prv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return &Account{
			PrivateKey: "",
			PublicKey:  "",
			Mnemonic:   "",
			Err:        errors.New("密钥生成失败"),
		}
	}
	return &Account{
		PrivateKey: hex.EncodeToString(prv),
		PublicKey:  hex.EncodeToString(pub),
		Mnemonic:   mnemonic,
		Err:        nil,
	}
}

// Get private key and public key by using mnemonic.Returns publickey,privatekey,error
func MnemonicToPrivateKey(mnemonic string) (string, string, error) {
	seed := bip39.NewSeed(mnemonic, "")
	seedForMultiVAC := seed[:32]
	reader := bytes.NewReader(seedForMultiVAC)
	pub, prv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", "", err
	} else {
		return hex.EncodeToString(pub), hex.EncodeToString(prv), nil
	}
}
