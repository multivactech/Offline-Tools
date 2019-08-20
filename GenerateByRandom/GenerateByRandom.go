package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io"
	"log"
	"os"
)

// PrivateKey is a byte array, []byte.
type PrivateKey ed25519.PrivateKey
type PublicKey ed25519.PublicKey

// Generate private key and public key by rand.
func GenerateKey(rand io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand)
	if err == nil {
		return PublicKey(pubKey), PrivateKey(privKey), nil
	} else {
		return nil, nil, err
	}
}
func main() {
	pubKey, prvKey, err := GenerateKey(nil)
	if err != nil {
		fmt.Println("出错了，请重启试试")
		log.Println(err)
		os.Exit(0)
	}
	fmt.Println("私钥(private key)：", hex.EncodeToString(prvKey))
	fmt.Println("公钥(public key)：", hex.EncodeToString(pubKey))
}
