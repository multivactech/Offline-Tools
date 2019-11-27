package signature

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

type PrivateKey ed25519.PrivateKey

// Sign the data with a private key.
func Sign(privateKey string, message string) ([]byte, error) {
	binaryPrv, err := IsLegal(privateKey)
	if err != nil {
		return nil, fmt.Errorf("illegal private key,err:%v", err)
	}
	binaryMsg, err := hex.DecodeString(string(message))
	if err != nil {
		return nil, fmt.Errorf("signed data is illegal,err:%v", err)
	}
	return ed25519.Sign(ed25519.PrivateKey(binaryPrv), binaryMsg), nil
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
