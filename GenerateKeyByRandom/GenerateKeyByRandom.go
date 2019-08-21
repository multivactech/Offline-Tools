package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"os"
)
func main() {
	pubKey, prvKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("出现未知错误，请重试：", err)
		os.Exit(0)
	}
	fmt.Println("私钥(private key)：", hex.EncodeToString(prvKey))
	fmt.Println("公钥(public key)：", hex.EncodeToString(pubKey))
}
