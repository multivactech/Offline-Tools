package signature

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

// PrivateKey defines the data structure of MultiVAC project private key.
type PrivateKey ed25519.PrivateKey

type SignInfo struct {
	TxHex     string `json:"txhex"`
	SignData  string `json:"signdata"`
	PublicKey []byte `json:"pubkey"`
}

// Sign the data with a private key.
func Sign(privateKey string, message []byte) ([]byte, error) {
	binaryPrv, err := IsLegal(privateKey)
	if err != nil {
		return nil, fmt.Errorf("illegal private key,err:%v", err)
	}
	return ed25519.Sign(binaryPrv, message), nil
}

// IsLegal checks if the private key is legal.
func IsLegal(privateKey string) ([]byte, error) {
	if len(privateKey) != 128 {
		return nil, fmt.Errorf("private key length is wrong, length should be 128")
	}
	val, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return val, nil

}
