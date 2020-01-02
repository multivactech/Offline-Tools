package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/multivactech/Offline-Tools/Account"
	signature "github.com/multivactech/Offline-Tools/Signature"
	"github.com/multivactech/Offline-Tools/keystore"
	"github.com/multivactech/Offline-Tools/mnemonic"

	"github.com/spf13/cobra"
)

const v = "version 1.0"

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

	data, err := keystore.ReadJSON(args[0])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	prv, err := keystore.GetPrivatekeyFromKeystore(args[1], data)
	if err != nil {
		fmt.Println("出现未知错误:", err)
		return
	}
	fmt.Println("private key:", prv)

}

//args[0]: priv key args[1]: txhex
func sign(cmd *cobra.Command, args []string) {

	if len(args) != 2 {
		fmt.Println("args error")
		return
	}
	signInfo := UnzipBox(args[1])
	fmt.Println(signInfo)
	signData, _ := hex.DecodeString(signInfo[1])
	fmt.Println("a", signData)
	sig, err := signature.Sign(args[0], signData)
	fmt.Println("b", sig)
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKey, err := Account.PrivatekeyToPublickey(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}
	signReturn := hex.EncodeToString(sig)
	pubKeyReturn := hex.EncodeToString(pubKey)

	ans := signInfo[0] + "." + signReturn + "." + pubKeyReturn

	fmt.Println("sign success! message is:", ans)
}

func init() {
	rootCmd.AddCommand(cmdGenerate)
	rootCmd.AddCommand(cmdSign)
	cmdCover.AddCommand(cmdCoverByKeystore)
	cmdCover.AddCommand(cmdCoverByMnemonic)
	rootCmd.AddCommand(cmdCover)
	rootCmd.AddCommand(cmdVersion)
}

//Execute used to execute cobra command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

func main() {

	Execute()

}

var rootCmd = &cobra.Command{
	Use: "./tool []",
	Long: `
Welcome to the MultiVAC offline tool,which provides functions for generating accounts, restoring accounts, and signing transactions.
`,
}

var cmdGenerate = &cobra.Command{
	Use:   "generate [password]",
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

var cmdVersion = &cobra.Command{
	Use:   "version",
	Short: "print tool version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(v)
	},
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

//UnzipBox used to unzip input string
func UnzipBox(box string) []string {
	ans := strings.Split(box, ".")
	if len(ans) != 3 {
		return []string{}
	}
	return ans
}
