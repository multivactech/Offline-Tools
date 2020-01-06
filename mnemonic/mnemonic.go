package mnemonic

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ed25519"
)

// Account is the account data including public- and private- key and the corresponding mnemonic.
type Account struct {
	PrivateKey string
	PublicKey  string
	Mnemonic   string
}

// GenerateMnemonicByLength generate mnemonic and then use mnemonic to generate the private key and its public key.
func GenerateMnemonicByLength(length int) (*Account, error) {
	// Length of mnemonic must be in the key list in mneMap.If length is error，there will no mnemonic.
	mneMap := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}
	if _, ok := mneMap[length]; !ok {
		return nil, fmt.Errorf("illegal length, length must be (one of them):12，15，18，21，24")
	}
	bitSize := mneMap[length]
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random sequence,err:%v", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	mnemonic = strings.Trim(mnemonic, "\r\n")
	if err != nil {
		return nil, fmt.Errorf("mnemonic dictionary loading error,err:%v", err)
	}
	// Default that there is no password.
	seed := bip39.NewSeed(mnemonic, "")
	seedForMultiVAC := seed[:32]
	reader := bytes.NewReader(seedForMultiVAC)
	pub, prv, err := ed25519.GenerateKey(reader)
	hexPrv := hex.EncodeToString(prv)
	hexPub := hex.EncodeToString(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key，err:%v", err)
	}
	return &Account{
		PrivateKey: hexPrv,
		PublicKey:  hexPub,
		Mnemonic:   mnemonic,
	}, nil
}

// ToAccount get private key and public key by using mnemonic.Returns publickey,privatekey,error.
func ToAccount(mnemonic string) (string, string, error) {
	seed := bip39.NewSeed(mnemonic, "")
	seedForMultiVAC := seed[:32]
	reader := bytes.NewReader(seedForMultiVAC)
	pub, prv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(prv), nil

}
