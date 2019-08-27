package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
)

// KdfParam用于存储PBKDF2算法生成证书(密钥)用到的参数，必须满足：1.n为2的幂 2.p*r<2^30.
type KdfParam struct {
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	KeyLen int    `json:"keyLen"`
	Salt   []byte `json:"salt"`
}

// CipherParams用于存储aes-128-ctr加密算法所需要用的必要参数.
type CipherParams struct {
	//aes-128-ctr用到的初始化向量
	Iv []byte
}

// KeystoreJson用于进行json编码存储与本地.
type KeyStoreJson struct {
	Kdfparam     *KdfParam    `json:"kdfparam"`
	CipherParams CipherParams `json:"cipher_params"`
	Cipher       string       `json:"cipher"`
	CipherText   []byte       `json:"cipher_text"`
	Kdf          string       `json:"kdf"`
	Mac          []byte       `json:"mac"`
	Version      string       `json:"version"`
	Project      string       `json:"project"`
}

// generateCertificate根据输入的密码生成一个用于AES算法加密用到的证书（密钥）.
func generateCertificate(password []byte) ([]byte, *KdfParam, error) {
	var n int = 32768
	var r int = 8
	var p int = 1
	var kenLen int = 32
	var salt []byte = []byte("MultiVAC")
	certificate, err := scrypt.Key(password, salt, n, r, p, kenLen)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败，%v", err)
	}
	return certificate, &KdfParam{
		N:      n,
		R:      r,
		P:      p,
		KeyLen: kenLen,
		Salt:   salt,
	}, nil
}

// MakeKeyStore根据传入的密码和私钥进行加密在程序目录下生成一个json文件，返回文件名.
func MakeKeyStore(password, privateKey []byte) (string, error) {
	certificate, kdfparams, err := generateCertificate(password)
	if err != nil {
		return "", err
	}
	cipherText, iv, err := aesCtrCrypt(privateKey, certificate)
	if err != nil {
		return "", fmt.Errorf("加密失败，%v", err)
	}
	mac := crypto.Keccak256(certificate, cipherText)
	keyStoreFile := KeyStoreJson{
		Kdfparam: kdfparams,
		CipherParams: CipherParams{
			Iv: iv,
		},
		Cipher:     "aes-128-ctr",
		CipherText: cipherText,
		Kdf:        "PBKDF2",
		Mac:        mac,
		Version:    "1.0",
		Project:    "MultiVAC",
	}
	keystore2Json, err := json.Marshal(keyStoreFile)
	if err != nil {
		return "", fmt.Errorf("转化为json文件失败：%v", err)
	}
	CurrentTime := time.Now().Format("2006-1-2 15:04:05")
	fileName := fmt.Sprintf("./MultiVAC%v.json", CurrentTime)
	file, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("创建文件失败，%v", err)
	}
	defer file.Close()
	_, err = file.Write(keystore2Json)
	if err != nil {
		return "", fmt.Errorf("写入文件失败，%v", err)
	}
	return fileName[2:], nil
}

// aesCVrtCryPt使用aes-128-ctr密文进行加密和解密(Ctr模式的加密和解密都是同一个函数).
func aesCtrCrypt(text []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	// 指定初始向量,长度必须等于block的块尺寸
	iv := []byte("12345678MultiVAC")
	blockMode := cipher.NewCTR(block, iv)
	message := make([]byte, len(text))
	blockMode.XORKeyStream(message, text)
	return message, iv, nil
}

// ReadJson用于读取指定文件名的json文件，返回解密必要的数据:ciphertext,kdfparam,err
func ReadJson(fileName string) ([]byte, *KdfParam, []byte, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取json文件错误，%v", err)
	}
	var total KeyStoreJson
	err = json.Unmarshal(file, &total)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("json解析失败，%v", err)
	}
	saltString := string(total.Kdfparam.Salt)
	param := &KdfParam{
		N:      total.Kdfparam.N,
		R:      total.Kdfparam.R,
		P:      total.Kdfparam.P,
		KeyLen: 32,
		Salt:   []byte(saltString),
	}
	cipherText := total.CipherText
	return cipherText, param, total.Mac, nil
}

// GetPrivatekeyFromKeystore根据用户的密码和必要的参数对加密的私钥进行解密
func GetPrivatekeyFromKeystore(password string, params *KdfParam, cipherText []byte, mac []byte) (string, error) {
	certificate, err := scrypt.Key([]byte(password), params.Salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return "", fmt.Errorf("生成解密证书失败，%v", err)
	}
	jsonMac := crypto.Keccak256(certificate, cipherText)
	if bytes.Equal(mac, jsonMac) == false {
		return "", fmt.Errorf("Json被篡改或者密码错误无法解密")
	}
	privateKey, _, err := aesCtrCrypt([]byte(cipherText), certificate)
	if err != nil {
		return "", fmt.Errorf("解密失败，%v", err)
	}
	_, err = isLegal(string(privateKey))
	if err != nil {
		return "", fmt.Errorf("解密失败，json被篡改")
	}
	return string(privateKey), nil
}

// isLegal check if the private key is legal.
func isLegal(privateKey string) ([]byte, error) {
	if len(privateKey) != 128 {
		return nil, fmt.Errorf("长度错误")
	}
	if val, err := hex.DecodeString(privateKey); err != nil {
		return nil, err
	} else {
		return val, nil
	}
}

// GetAllJsonFiles read all json files in local folder.
func GetAllJsonFiles(path string, s []string) ([]string, error) {
	rd, err := ioutil.ReadDir(path)
	if err != nil {
		return s, err
	}
	for _, fi := range rd {
		if !fi.IsDir() {
			fullName := fi.Name()
			if strings.Contains(fullName, "json") {
				s = append(s, fullName)
			}
		}
	}
	return s, nil
}
