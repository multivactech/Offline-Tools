package Account

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

type PrivateKey ed25519.PrivateKey
type PublicKey ed25519.PublicKey

// GenerateAccount generate public key and private key for MultiVAC project.
func GenerateAccount() ([]byte, []byte, error) {
	pubKey, prvKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return pubKey, prvKey, nil
}

// PrivatekeyToPublickey get the public key for the input private key.
func PrivatekeyToPublickey(prv string) ([]byte, error) {
	if !isLegal(prv) {
		return nil, fmt.Errorf("私钥不合法")
	}
	prvToBinary, err := hex.DecodeString(prv)
	if err != nil {
		return nil, err
	}
	prvKey := PrivateKey(prvToBinary)
	pubKey := prvKey.public()
	return pubKey, nil
}

// isLegal check whether the private key is legal for MultiVAC Project.
func isLegal(privateKey string) bool {
	if len(privateKey) != 128 {
		return false
	}
	if _, err := hex.DecodeString(privateKey); err != nil {
		return false
	}
	return true
}

// public using private key to get its public key.
func (priv PrivateKey) public() PublicKey {
	privateKey := ed25519.PrivateKey(priv)
	publicKey := privateKey.Public()
	return PublicKey(publicKey.(ed25519.PublicKey))
}
