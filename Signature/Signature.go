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

func main() {
	fmt.Println("输入私钥(input you private key):")
	privateKeyReader := bufio.NewReader(os.Stdin)
	privateKey, err := privateKeyReader.ReadString('\n')
	if err != nil {
		fmt.Println("读取私钥错误", err)
		os.Exit(0)
	}
	privateKey = strings.Trim(privateKey, "\r\n")
	if check(privateKey) {
		prvToBinary, _ := hex.DecodeString(privateKey)
		fmt.Println("输入需要签名的数据(input data need to be signed):")
		txReader := bufio.NewReader(os.Stdin)
		txString, err := txReader.ReadString('\n')
		if err != nil {
			fmt.Println("读取数据错误：", err)
			os.Exit(0)
		}
		txString = strings.Trim(txString, "\r\n")
		tx, err := hex.DecodeString(txString)
		if err != nil {
			fmt.Println("需要签名的数据不合法(The transaction that needs to be signed is illegal)")
			os.Exit(0)
		} else {
			signature := sign(prvToBinary, tx)
			fmt.Println("签名的消息(signature of data):", hex.EncodeToString(signature))
		}
	} else {
		fmt.Println("私钥不合法(Private key is illegal)")
		os.Exit(0)
	}
}

// Sign the data with a private key.
func sign(privateKey PrivateKey, message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message)
}

// Check if the private key is legal.
func check(prvKey string) bool {
	if len(prvKey) != 128 {
		return false
	}
	if _, err := hex.DecodeString(prvKey); err != nil {
		return false
	}
	return true

}
