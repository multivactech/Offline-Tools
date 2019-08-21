package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"os"
	"strings"
)

type PrivateKey ed25519.PrivateKey
type PublicKey ed25519.PublicKey

func main() {
	fmt.Println("输入私钥(input your private key):")
	cmdReader := bufio.NewReader(os.Stdin)
	privateKeyString, err := cmdReader.ReadString('\n')
	if err != nil {
		fmt.Println("读取私钥错误")
		os.Exit(0)
	}
	privateKeyString = strings.Trim(privateKeyString, "\r\n")
	prvToBinary, err := hex.DecodeString(privateKeyString)
	if (err != nil) || (len(privateKeyString) != 128) {
		fmt.Println("输入的私钥有错误")
		os.Exit(0)
	} else {
		prvKey := PrivateKey(prvToBinary)
		pubKey := prvKey.Public()
		fmt.Println("生成的公钥(your public key):", hex.EncodeToString(pubKey))
	}

}

// Using the input private key to generate the public key.
func (priv PrivateKey) Public() PublicKey {
	privateKey := ed25519.PrivateKey(priv)
	publicKey := privateKey.Public()
	return PublicKey(publicKey.(ed25519.PublicKey))
}
