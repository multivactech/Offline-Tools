package main

import (
	"fmt"
	"github.com/multivactech/Offline-Tools/keystore"
	"github.com/multivactech/Offline-Tools/mnemonic"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func generate(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Println("args error")
		return
	}
	account, _ := mnemonic.GenerateMnemonicByLength(24)
	fileName, _ := keystore.MakeKeyStore([]byte(args[0]), []byte(account.PrivateKey))
	fmt.Println("generate success!")
	fmt.Println("public key:", account.PublicKey)
	fmt.Println("private key:", account.PrivateKey)
	fmt.Println("mnemonic:", account.Mnemonic)
	fmt.Println("keystore file:", fileName)
}

func coverByMnemonic(cmd *cobra.Command, args []string) {
	if len(args) != 24 {
		fmt.Println("args error")
		return
	}
	mne := ""
	for i := range args {
		if i != 0 {
			mne += " "
		}
		mne += args[i]
	}
	fmt.Println(len(mne), mne)

	pub, prv, err := mnemonic.MnemonicToAccount(mne)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("public key:", pub)
	fmt.Println("private key:", prv)

}

func coverByKeystore(cmd *cobra.Command, args []string) {
	if len(args) != 2 {
		fmt.Println("args error")
		return
	}

	data, err := keystore.ReadJson(args[0])
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	prv, err := keystore.GetPrivatekeyFromKeystore(args[1], data)

	fmt.Println("private key:", prv)

}

func sign(cmd *cobra.Command, args []string) {
/*
	if len(args) != 2 {
		fmt.Println("args error")
		return
	}
	_, signInfo := unzipBox(args[1])
	sig, err := signature.Sign(args[0], []byte(signInfo))
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := Account.PrivatekeyToPublickey(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("sign success! message is:", string(sig))*/
}

func init() {
	rootCmd.AddCommand(cmdGenerate)
	rootCmd.AddCommand(cmdSign)
	cmdCover.AddCommand(cmdCoverByKeystore)
	cmdCover.AddCommand(cmdCoverByMnemonic)
	rootCmd.AddCommand(cmdCover)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

func main() {

	Execute()

}

var rootCmd = &cobra.Command{}

var cmdGenerate = &cobra.Command{
	Use:   "generate",
	Short: "generate account",
	Run:   generate,
}

var cmdCover = &cobra.Command{
	Use:   "cover [sub]",
	Short: "cover account",
}

var cmdSign = &cobra.Command{
	Use:   "sign [private key] [sign message]",
	Short: "sign a message",
	Run:   sign,
}

var cmdCoverByMnemonic = &cobra.Command{
	Use:   "bymnemonic [mneonic]...",
	Short: "cover by mnemonic",
	Run:   coverByMnemonic,
}

var cmdCoverByKeystore = &cobra.Command{
	Use:   "bykeystore [keystore path] [password]",
	Short: "cover by keystore",
	Run:   coverByKeystore,
}

func unzipBox(box string) ([]string) {
	ans := strings.Split(box, "&!")
	if len(ans) != 3 {
		return []string{}
	}
	return ans
}

func zipBox(txHex string, signInfo []byte, pubKey []byte) string {
	return txHex + "&!" + string(signInfo) + "&!" + string(pubKey)
}
