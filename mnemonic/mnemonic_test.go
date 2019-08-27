package mnemonic

import (
	"fmt"
	"testing"
)

func TestMnemonicToPrivateKey(t *testing.T) {
	var mne string = "guess merry multiply diesel injury obtain join peace autumn burger muscle detail day bid mansion nerve trash cloud mail casual genre bright visual mad"
	_, prv, _ := MnemonicToAccount(mne)
	if prv == "6f8de1bb0e08e08f8c660869e837f539f8bc9ec5da16b37fdb7b46cd5e89e75d9e6c3be8b551297a98e11c85b8e2c2a66db582954c6e4ee744d8b37a40445b7e" {
		t.Log("pass")
	} else {
		t.Error("failed")
	}
}
func TestGenerateMnemonicByLength(t *testing.T) {
	account, err := GenerateMnemonicByLength(12)
	if err == nil {
		t.Log("pass")
	}
	fmt.Println(account)
}
