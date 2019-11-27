package Account

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

// PrivateKey defines the data structure of MultiVAC project private key.
type PrivateKey ed25519.PrivateKey
// PublicKey defines the data structure of MultiVAC project public key.
type PublicKey ed25519.PublicKey

// GenerateAccount generate public key and private key for MultiVAC project.
func GenerateAccount() (PublicKey, PrivateKey, error) {
	pubKey, prvKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return PublicKey(pubKey), PrivateKey(prvKey), nil
}

// PrivatekeyToPublickey get the public key for the input private key.
func PrivatekeyToPublickey(prv string) (PublicKey, error) {
	prvToBinary, err := isLegal(prv)
	if err != nil {
		return nil, fmt.Errorf("illegal private key,err:%v", err)
	}
	prvKey := PrivateKey(prvToBinary)
	pubKey := prvKey.public()
	return pubKey, nil
}

// isLegal check whether the private key is legal for MultiVAC Project.
func isLegal(privateKey string) ([]byte, error) {
	if len(privateKey) != 128 {
		return nil, fmt.Errorf("error length")
	}
	val, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return val, nil

}

// public using private key to get its public key.
func (priv PrivateKey) public() PublicKey {
	privateKey := ed25519.PrivateKey(priv)
	publicKey := privateKey.Public()
	return PublicKey(publicKey.(ed25519.PublicKey))
}
