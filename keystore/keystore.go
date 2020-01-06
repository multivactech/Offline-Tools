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
	"runtime"
	"time"

	crypto2 "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
)

// KdfParam is used to store the parameters used by the PBKDF2 algorithm to generate the certificate.
type KdfParam struct {
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	KeyLen int    `json:"keyLen"`
	Salt   []byte `json:"salt"`
}

// CipherParams is used to store the necessary parameters required by the aes-128-ctr encryption algorithm.
type CipherParams struct {
	// aes-128-ctr initialization vector
	Iv []byte
}

// JSON is used for json encoding storage and local.
type JSON struct {
	Kdfparam     *KdfParam    `json:"kdfparam"`
	CipherParams CipherParams `json:"cipher_params"`
	Cipher       string       `json:"cipher"`
	CipherText   []byte       `json:"cipher_text"`
	Kdf          string       `json:"kdf"`
	Mac          []byte       `json:"mac"`
	Version      string       `json:"version"`
	Project      string       `json:"project"`
}

// generateCertificate generates a certificate for AES algorithm encryption based on the entered password.
func generateCertificate(password []byte) ([]byte, *KdfParam, error) {
	var n = 32768
	var r = 8
	var p = 1
	var kenLen = 32
	var salt = []byte("MultiVAC")
	certificate, err := scrypt.Key(password, salt, n, r, p, kenLen)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败，err:%v", err)
	}
	return certificate, &KdfParam{
		N:      n,
		R:      r,
		P:      p,
		KeyLen: kenLen,
		Salt:   salt,
	}, nil
}

// MakeKeyStore encrypts the incoming password and private key to
// generate a json file in the program directory and returns the filename.
func MakeKeyStore(password, privateKey []byte) (string, error) {
	keyStoreFile, err := CreateKeyStore(password, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create keystore:err:%v", err)
	}
	keystore2Json, err := json.MarshalIndent(keyStoreFile, " ", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to convert to json:err:%v", err)
	}
	var fileName string
	filePath, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get file path,err:%v", err)
	}
	CurrentTime := time.Now().Format("2006-1-2-15-04-05")
	if runtime.GOOS == "windows" {
		_, err := os.Stat(filePath)
		if err != nil {
			err := os.Mkdir(filePath, os.ModePerm)
			if err != nil {
				return "", fmt.Errorf("failed to create keystore folder,err:%v", err)
			}
		}
		fileName = filePath + "MultiVAC" + CurrentTime + ".json"
	} else {
		_, err := os.Stat(filePath)
		if err != nil {
			err := os.Mkdir(filePath, os.ModePerm)
			if err != nil {
				return "", fmt.Errorf("failed to create folder,err:%v", err)
			}
		}
		fileName = filePath + "/MultiVAC" + CurrentTime + ".json"
	}
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		return "", fmt.Errorf("can not create file，err:%v", err)
	}
	_, err = file.Write(keystore2Json)
	if err != nil {
		return "", fmt.Errorf("failed to write data to file，err:%v", err)
	}
	return fileName, nil
}

//CreateKeyStore create a keystore structure
func CreateKeyStore(password, privateKey []byte) (JSON, error) {
	certificate, kdfparams, err := generateCertificate(password)
	if err != nil {
		return JSON{}, err
	}
	cipherText, iv, err := aesCtrCrypt(privateKey, certificate)
	if err != nil {
		return JSON{}, err
	}
	mac := crypto2.Keccak256(certificate, cipherText)
	keyStore := JSON{
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
	return keyStore, nil
}

// aesCVrtCryPt uses aes-128-ctr ciphertext for encryption and decryption.
func aesCtrCrypt(text []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	// Specify the initial vector, the length must be equal to the block size of the block.
	iv := []byte("12345678MultiVAC")
	blockMode := cipher.NewCTR(block, iv)
	message := make([]byte, len(text))
	blockMode.XORKeyStream(message, text)
	return message, iv, nil
}

// ReadJSON is used to read a json file with the specified file name and return the keystore data structure.
func ReadJSON(fileName string) (JSON, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return JSON{}, fmt.Errorf("fail to read file，err:%v", err)
	}
	var total JSON
	err = json.Unmarshal(file, &total)
	if err != nil {
		return JSON{}, fmt.Errorf("fail to read data from json，err:%v", err)
	}
	return total, nil
}

// GetPrivatekeyFromKeystore decrypts the encrypted private key based on the user's password and necessary parameters.
func GetPrivatekeyFromKeystore(password string, keystore JSON) (string, error) {
	params := keystore.Kdfparam
	cipherText := keystore.CipherText
	mac := keystore.Mac
	certificate, err := scrypt.Key([]byte(password), params.Salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return "", fmt.Errorf("failed to generate certificate，err:%v", err)
	}
	jsonMac := crypto2.Keccak256(certificate, cipherText)
	if !bytes.Equal(mac, jsonMac) {
		return "", fmt.Errorf("the json is tampered or the password cannot be decrypted")
	}
	privateKey, _, err := aesCtrCrypt(cipherText, certificate)
	if err != nil {
		return "", fmt.Errorf("decryption failed，err:%v", err)
	}
	_, err = isLegal(string(privateKey))
	if err != nil {
		return "", fmt.Errorf("decryption failed, json was tampered,err:%v", err)
	}
	return string(privateKey), nil
}

// isLegal checks if the private key is legal.
func isLegal(privateKey string) ([]byte, error) {
	if len(privateKey) != 128 {
		return nil, fmt.Errorf("invalid length of private key")
	}
	val, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return val, nil

}
