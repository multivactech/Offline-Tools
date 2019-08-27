package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"MultiVACTools/Account"
	signature "MultiVACTools/Signature"
	"MultiVACTools/keystore"
	"MultiVACTools/mnemonic"
)

func main() {
	showMainMenu()
	bufReader := bufio.NewReader(os.Stdin)
	inByte, err := bufReader.ReadByte()
	if err != nil {
		fmt.Println("读取键盘输入错误")
		os.Exit(0)
	}
	switch inByte - 48 {
	case 1:
		showAccountMenu()
		bufReader = bufio.NewReader(os.Stdin)
		inByte, err = bufReader.ReadByte()
		if err != nil {
			fmt.Println("读取键盘输入错误")
			os.Exit(0)
		}
		switch inByte - 48 {
		case 1:
			// Use mnemonic to generate account.
			func() {
				account, err := mnemonic.GenerateMnemonicByLength(12)
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fmt.Println("助记词:", account.Mnemonic)
				fmt.Println("私钥:", account.PrivateKey)
				fmt.Println("公钥:", account.PublicKey)
				fmt.Println("=======================")
				fmt.Println("是否生成keystore？1.生成；其他退出")
				fmt.Printf("请输入:")
				bufReader := bufio.NewReader(os.Stdin)
				inByte, err := bufReader.ReadByte()
				if err != nil {
					fmt.Println("读取键盘输入错误")
					os.Exit(0)
				}
				if int(inByte)-48 != 1 {
					os.Exit(0)
				}
				fmt.Printf("输入加密的密码:")
				bufReader = bufio.NewReader(os.Stdin)
				pass, err := bufReader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				pass = strings.Trim(pass, "\r\n")
				fileName, err := keystore.MakeKeyStore([]byte(pass), []byte(account.PrivateKey))
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fmt.Println("keystore已经生成到当前目录，文件名:", fileName)
			}()
		case 2:
			// Generate account only.
			func() {
				pub, prv, err := Account.GenerateAccount()
				if err != nil {
					fmt.Println("出现异常:", err)
					os.Exit(0)
				}
				prvString := hex.EncodeToString(prv)
				pubString := hex.EncodeToString(pub)
				fmt.Println("私钥:", prvString)
				fmt.Println("公钥:", pubString)
				fmt.Println("=======================")
				fmt.Println("是否生成keystore？1.生成；其他退出")
				fmt.Printf("请输入:")
				bufReader := bufio.NewReader(os.Stdin)
				inByte, err := bufReader.ReadByte()
				if err != nil {
					fmt.Println("读取键盘输入错误")
					os.Exit(0)
				}
				if int(inByte)-48 != 1 {
					os.Exit(0)
				}
				fmt.Printf("输入加密的密码:")
				bufReader = bufio.NewReader(os.Stdin)
				pass, err := bufReader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				pass = strings.Trim(pass, "\r\n")
				fileName, err := keystore.MakeKeyStore([]byte(pass), []byte(prvString))
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fmt.Println("keystore已经生成到当前目录，文件名:", fileName)
			}()
		default:
			os.Exit(0)
		}
	case 2:
		showPrivateMenu()
		bufReader = bufio.NewReader(os.Stdin)
		inByte, err = bufReader.ReadByte()
		if err != nil {
			fmt.Println("读取键盘输入错误")
			os.Exit(0)
		}
		switch inByte - 48 {
		case 1:
			// Use mnemonic to get private key.
			func() {
				fmt.Printf("输入助记词:")
				bufReader = bufio.NewReader(os.Stdin)
				mne, err := bufReader.ReadString('\n')
				mne = strings.Trim(mne, "\r\n")
				if err != nil {
					fmt.Println("读取私钥错误")
					os.Exit(0)
				}
				pub, prv, err := mnemonic.MnemonicToAccount(mne)
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fmt.Println(len(prv))
				fmt.Println("私钥:", prv)
				fmt.Println("公钥:", pub)
				fmt.Println("=======================")
				fmt.Println("是否生成keystore？1.生成；其他退出")
				fmt.Printf("请输入:")
				bufReader := bufio.NewReader(os.Stdin)
				inByte, err := bufReader.ReadByte()
				if err != nil {
					fmt.Println("读取键盘输入错误")
					os.Exit(0)
				}
				if int(inByte)-48 != 1 {
					os.Exit(0)
				}
				fmt.Printf("输入加密的密码:")
				bufReader = bufio.NewReader(os.Stdin)
				pass, err := bufReader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				pass = strings.Trim(pass, "\r\n")
				fileName, err := keystore.MakeKeyStore([]byte(pass), []byte(prv))
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fmt.Println("keystore已经生成到当前目录，文件名:", fileName)
			}()
		case 2:
			// Use password to get private key in keystore.
			func() {
				var fileSlice []string
				dir, err := os.Getwd()
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fileSlice, err = keystore.GetAllJsonFiles(dir, fileSlice)
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				if len(fileSlice) == 0 {
					fmt.Println("在程序当前目录下没有发现keystore文件")
					os.Exit(0)
				}
				fmt.Printf("编号\t  文件名\n")
				for in, val := range fileSlice {
					fmt.Printf("%d\t %v\n", in, val)
				}
				fmt.Printf("选择需要解密的keystore的编号:")
				bufReader := bufio.NewReader(os.Stdin)
				inByte, err := bufReader.ReadString('\n')
				inByte = strings.Trim(inByte, "\r\n")
				if err != nil {
					fmt.Println("读取键盘输入错误")
					os.Exit(0)
				}
				index, err := strconv.Atoi(inByte)
				if err != nil {
					fmt.Println("读取键盘输入错误")
					os.Exit(0)
				}
				if index > len(fileSlice)-1 || index < 0 {
					fmt.Println("输入编号有误")
					os.Exit(0)
				}
				jsonName := fileSlice[index]
				fmt.Printf("输入解锁的密码:")
				bufReader = bufio.NewReader(os.Stdin)
				pass, err := bufReader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				pass = strings.Trim(pass, "\r\n")
				ciphertext, params, mac, err := keystore.ReadJson(jsonName)
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				prv, err := keystore.GetPrivatekeyFromKeystore(pass, params, ciphertext, mac)
				if err != nil {
					fmt.Println(err)
					os.Exit(0)
				}
				fmt.Println("解密后私钥：", prv)
				pub, err := Account.PrivatekeyToPublickey(prv)
				fmt.Println("公钥:", hex.EncodeToString(pub))

			}()
		default:
			os.Exit(0)
		}
	case 3:
		// Get public key from private key.
		func() {
			fmt.Printf("输入私钥:")
			cmdReader := bufio.NewReader(os.Stdin)
			privateKeyString, err := cmdReader.ReadString('\n')
			privateKeyString = strings.Trim(privateKeyString, "\r\n")
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			pub, err := Account.PrivatekeyToPublickey(privateKeyString)
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			fmt.Println("对应的公钥:", hex.EncodeToString(pub))
			fmt.Println("=======================")
			fmt.Println("是否生成keystore？1.生成；其他退出")
			fmt.Printf("请输入:")
			bufReader := bufio.NewReader(os.Stdin)
			inByte, err := bufReader.ReadByte()
			if err != nil {
				fmt.Println("读取键盘输入错误")
				os.Exit(0)
			}
			if int(inByte)-48 != 1 {
				os.Exit(0)
			}
			fmt.Printf("输入加密的密码:")
			bufReader = bufio.NewReader(os.Stdin)
			pass, err := bufReader.ReadString('\n')
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			pass = strings.Trim(pass, "\r\n")
			fileName, err := keystore.MakeKeyStore([]byte(pass), []byte(privateKeyString))
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			fmt.Println("keystore已经生成到当前目录，文件名:", fileName)
		}()
	case 4:
		// Sign the transaction by using private key.
		func() {
			fmt.Printf("输入私钥:")
			cmdReader := bufio.NewReader(os.Stdin)
			privateKeyString, err := cmdReader.ReadString('\n')
			privateKeyString = strings.Trim(privateKeyString, "\r\n")
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			_, err = signature.IsLegal(privateKeyString)
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			fmt.Println("输入需要签名的数据:")
			cmdReader = bufio.NewReader(os.Stdin)
			transaction, err := cmdReader.ReadString('\n')
			transaction = strings.Trim(transaction, "\r\n")
			sig, err := signature.Sign(privateKeyString, transaction)
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			fmt.Println("签名的消息为:", hex.EncodeToString(sig))
		}()
	default:
		os.Exit(0)
	}
}
func showMainMenu() {
	fmt.Println("=======================")
	fmt.Println("MultiVAC离线工具:")
	fmt.Println("1.生成新账户")
	fmt.Println("2.找回私钥")
	fmt.Println("3.找回公钥")
	fmt.Println("4.签名交易")
	fmt.Println("其他字符退出")
	fmt.Printf("请输入:")
}
func showAccountMenu() {
	fmt.Println("=======================")
	fmt.Println("1.使用助记词生成私钥和公钥")
	fmt.Println("2.直接生成私钥和公钥")
	fmt.Println("其他字符退出")
	fmt.Printf("请输入:")
}
func showPrivateMenu() {
	fmt.Println("=======================")
	fmt.Println("1.根据助记词找回私钥")
	fmt.Println("2.根据Keystore找回")
	fmt.Println("其他字符退出")
	fmt.Printf("请输入:")
}
