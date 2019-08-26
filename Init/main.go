package main

import (
	"MultiVACTools/keystore"
	"MultiVACTools/mnemonic"
	"fmt"
	"os"
)

func main() {

	// Todo:带重构完其他模块一起整合
	// 简单的测试用例，等重构完其他部分再一起修改
	account, _ := mnemonic.GenerateMnemonicByLength(24)
	fmt.Println("助记词:", account.Mnemonic)
	fmt.Println("私钥", account.PrivateKey)
	fmt.Println("公钥", account.PublicKey)

	// 根据助记词找回私钥(注意空格)
	// 助记词： guess merry multiply diesel injury obtain join peace autumn burger
	// muscle detail day bid mansion nerve trash cloud mail casual genre bright visual mad
	// 私钥：6f8de1bb0e08e08f8c660869e837f539f8bc9ec5da16b37fdb7b46cd5e89e75d9e
	// 6c3be8b551297a98e11c85b8e2c2a66db582954c6e4ee744d8b37a40445b7e
	// 公钥:9e6c3be8b551297a98e11c85b8e2c2a66db582954c6e4ee744d8b37a40445b7e
	// 注：私钥公钥都符合MultiVAC项目
	mne := "guess merry multiply diesel injury obtain join peace autumn burger muscle detail day bid mansion nerve trash cloud mail casual genre bright visual mad"
	pub, prv, err := mnemonic.MnemonicToPrivateKey(mne)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	} else {
		fmt.Println("私钥", prv)
		fmt.Println("公钥", pub)
	}
	privatekey := prv
	pass := []byte("linglinger")
	filename, _ := keystore.MakeKeyStore(pass, []byte(privatekey))
	fmt.Println("未加密的私钥：", privatekey)
	fmt.Println("生成的文件为：", filename)
	ciphertext, params, mac, err := keystore.ReadJson(filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	prv2, err := keystore.GetPrivatekeyFromKeystore(string(pass), params, ciphertext, mac)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println("解密后私钥：", prv2)

}
