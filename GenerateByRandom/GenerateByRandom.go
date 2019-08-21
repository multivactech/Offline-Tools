package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io"
	"os"
)

// PrivateKey is a byte array, []byte.
type PrivateKey ed25519.PrivateKey
type PublicKey ed25519.PublicKey

// Generate private key and public key by rand.If rand is nil,use the os rand seed.
func GenerateKey(rand io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	return PublicKey(pubKey), PrivateKey(privKey), nil
}
func main() {
	pubKey, prvKey, err := GenerateKey(nil)
	if err != nil {
		fmt.Println("出现未知错误，请重试：", err)
		os.Exit(0)
	}
	fmt.Println("私钥(private key)：", hex.EncodeToString(prvKey))
	fmt.Println("公钥(public key)：", hex.EncodeToString(pubKey))
}
