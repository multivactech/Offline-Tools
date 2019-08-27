package signature

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

type PrivateKey ed25519.PrivateKey

//func main() {
//	fmt.Println("输入私钥(input you private key):")
//	privateKeyReader := bufio.NewReader(os.Stdin)
//	privateKey, err := privateKeyReader.ReadString('\n')
//	if err != nil {
//		fmt.Println("读取私钥错误", err)
//		os.Exit(0)
//	}
//	privateKey = strings.Trim(privateKey, "\r\n")
//	if check(privateKey) {
//		prvToBinary, _ := hex.DecodeString(privateKey)
//		fmt.Println("输入需要签名的数据(input data need to be signed):")
//		txReader := bufio.NewReader(os.Stdin)
//		txString, err := txReader.ReadString('\n')
//		if err != nil {
//			fmt.Println("读取数据错误：", err)
//			os.Exit(0)
//		}
//		txString = strings.Trim(txString, "\r\n")
//		tx, err := hex.DecodeString(txString)
//		if err != nil {
//			fmt.Println("需要签名的数据不合法(The transaction that needs to be signed is illegal)")
//			os.Exit(0)
//		} else {
//			signature := sign(prvToBinary, tx)
//			fmt.Println("签名的消息(signature of data):", hex.EncodeToString(signature))
//		}
//	} else {
//		fmt.Println("私钥不合法(Private key is illegal)")
//		os.Exit(0)
//	}
//}

// Todo：test them
// Sign the data with a private key.
func Sign(privateKey string, message string) ([]byte, error) {
	if !isLegal(privateKey) {
		return nil, fmt.Errorf("私钥不合法")
	}
	_, err := hex.DecodeString(string(message))
	if err != nil {
		return nil, fmt.Errorf("签名的数据不合法")
	}
	// 已经在上面进行来检测，所以这里不需要处理错误
	prv2Binary, _ := hex.DecodeString(privateKey)
	msg2Binary, _ := hex.DecodeString(message)
	return ed25519.Sign(ed25519.PrivateKey(prv2Binary), msg2Binary), nil
}

// isLegal checks if the private key is legal.
func isLegal(privateKey string) bool {
	if len(privateKey) != 128 {
		return false
	}
	if _, err := hex.DecodeString(privateKey); err != nil {
		return false
	}
	return true
}
