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
		return nil, fmt.Errorf("私钥不合法,err:%v", err)
	}
	binaryMsg, err := hex.DecodeString(string(message))
	if err != nil {
		return nil, fmt.Errorf("签名的数据不合法,err:%v", err)
	}
	// 已经在上面进行来检测，所以这里不需要处理错误.
	return ed25519.Sign(ed25519.PrivateKey(binaryPrv), binaryMsg), nil
}

// isLegal checks if the private key is legal.
func IsLegal(privateKey string) ([]byte, error) {
	if len(privateKey) != 128 {
		return nil, fmt.Errorf("私钥长度错误，长度应该为128")
	}
	val, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return val, nil

}
