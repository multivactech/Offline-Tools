package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"os"
	time2 "time"
)

type KdfParam struct {
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	KeyLen int    `json:"keyLen"`
	Salt   []byte `json:"salt"`
}
type CipherParams struct {
	Iv []byte
}
type KeyStoreJson struct {
	Kdfparam     KdfParam     `json:"kdfparam"`
	CipherParams CipherParams `json:"cipher_params"`
	Cipher       string       `json:"cipher"`
	CipherText   []byte       `json:"cipher_text"`
	Kdf          string       `json:"kdf"`
	Version      string       `json:"version"`
	Project      string       `json:"project"`
}

// generateCertificate根据输入的密码生成一个用于AES算法加密用到的证书（密钥）
func generateCertificate(password []byte) ([]byte, KdfParam, error) {
	var n int = 32768
	var r int = 8
	var p int = 1
	var kenLen int = 32
	var salt []byte = []byte("MultiVAC")
	certificate, err := scrypt.Key(password, salt, n, r, p, kenLen)
	if err != nil {

		return nil, KdfParam{
			N:      0,
			R:      0,
			P:      0,
			KeyLen: 0,
			Salt:   nil,
		}, fmt.Errorf("生成证书失败，%v", err)
	}
	return certificate, KdfParam{
		N:      n,
		R:      r,
		P:      p,
		KeyLen: kenLen,
		Salt:   salt,
	}, nil
}

// MakeKeyStore根据传入的密码和私钥进行加密在程序目录下生成一个json文件，返回文件名
func MakeKeyStore(password, privateKey []byte) (string, error) {
	certificate, kdfparams, err := generateCertificate(password)
	if err != nil {
		return "", fmt.Errorf("%v", err)
	}
	cipherText, iv, err := aesCtrCrypt(privateKey, certificate)
	if err != nil {
		return "", fmt.Errorf("加密失败，%v", err)
	}
	keyStoreFile := KeyStoreJson{
		Kdfparam: kdfparams,
		CipherParams: CipherParams{
			Iv: iv,
		},
		Cipher:     "aes-128-ctr",
		CipherText: cipherText,
		Kdf:        "PDKDF2",
		Version:    "1.0",
		Project:    "MultiVAC",
	}
	keystore2Json, err := json.Marshal(keyStoreFile)
	if err != nil {
		return "", fmt.Errorf("转化为json文件失败：%v", err)
	}
	time := time2.Now().String()
	fileName := fmt.Sprintf("MultiVAC%v.json", time)
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		return "", fmt.Errorf("创建文件失败，%v", err)
	}
	_, err = file.Write(keystore2Json)
	if err != nil {
		return "", fmt.Errorf("写入文件失败，%v", err)
	}
	return fileName, nil

}

// aesCVrtCryPt使用aes-128-ctr密文进行加密和解密(Ctr模式的加密和解密都是同一个函数)
func aesCtrCrypt(text []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%v", err)
	}
	// 指定初始向量,长度必须等于block的块尺寸
	iv := []byte("12345678MultiVAC")
	blockMode := cipher.NewCTR(block, iv)
	message := make([]byte, len(text))
	blockMode.XORKeyStream(message, text)
	return message, iv, nil
}

// ReadJson用于读取指定文件名的json文件，返回解密必要的数据:ciphertext,kdfparam,err
func ReadJson(fileName string) ([]byte, KdfParam, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, KdfParam{
			N:      0,
			R:      0,
			P:      0,
			KeyLen: 0,
			Salt:   nil,
		}, fmt.Errorf("读取json文件错误，%v", err)
	}
	var total KeyStoreJson
	err = json.Unmarshal(file, &total)
	if err != nil {
		return nil, KdfParam{
			N:      0,
			R:      0,
			P:      0,
			KeyLen: 0,
			Salt:   nil,
		}, fmt.Errorf("json解析失败，%v", err)
	}
	saltString := string(total.Kdfparam.Salt)
	param := KdfParam{
		N:      total.Kdfparam.N,
		R:      total.Kdfparam.R,
		P:      total.Kdfparam.P,
		KeyLen: 32,
		Salt:   []byte(saltString),
	}
	cipherText := total.CipherText
	return cipherText, param, nil
}

// GetPrivatekeyFromKeystore根据用户的密码和必要的参数对加密的私钥进行解密
func GetPrivatekeyFromKeystore(password string, params KdfParam, cipherText []byte) (string, error) {
	certificate, err := scrypt.Key([]byte(password), params.Salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return "", fmt.Errorf("生成解密证书失败，%v", err)
	}
	privateKey, _, err := aesCtrCrypt([]byte(cipherText), certificate)
	if err != nil {
		return "", fmt.Errorf("获取私钥失败，确认是否json被修改，%v", err)
	}
	return string(privateKey), nil
}
