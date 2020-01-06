package mnemonic

import (
	"strings"
	"testing"
)

func TestMnemonicToAccount(t *testing.T) {
	type args struct {
		mnemonic string
	}
	tests := []struct {
		name    string
		args    args
		wantPk  string
		wantSk  string
		wantErr bool
	}{
		{
			name:    "test#1",
			args:    args{mnemonic: "guess merry multiply diesel injury obtain join peace autumn burger muscle detail day bid mansion nerve trash cloud mail casual genre bright visual mad"},
			wantPk:  "9e6c3be8b551297a98e11c85b8e2c2a66db582954c6e4ee744d8b37a40445b7e",
			wantSk:  "6f8de1bb0e08e08f8c660869e837f539f8bc9ec5da16b37fdb7b46cd5e89e75d9e6c3be8b551297a98e11c85b8e2c2a66db582954c6e4ee744d8b37a40445b7e",
			wantErr: false,
		},

		{
			name:    "test#2",
			args:    args{mnemonic: "sting business fog copy citizen west table angry enact melody unusual logic denial smile major size life welcome bitter menu venue city own blur"},
			wantPk:  "d22e936a15aa414ff89b478488293a2a87452d35aa674e06b5e93a9ae9dc5272",
			wantSk:  "aa7ac0a9aaf8bd2cc537a8e50a758dda0b35e09287316e0fbbe36779b185cff4d22e936a15aa414ff89b478488293a2a87452d35aa674e06b5e93a9ae9dc5272",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ToAccount(tt.args.mnemonic)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToAccount() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantPk {
				t.Errorf("ToAccount() got = %v, want_pk %v", got, tt.wantPk)
			}
			if got1 != tt.wantSk {
				t.Errorf("ToAccount() got1 = %v, want_sk %v", got1, tt.wantSk)
			}
		})
	}
}

func TestGenerateMnemonicByLength(t *testing.T) {
	type args struct {
		length int
	}
	tests := []struct {
		name    string
		args    args
		want    *Account
		wantErr bool
	}{
		{
			name: "test#1",
			args: args{length: 24},
			want: &Account{
				Mnemonic: "sting business fog copy citizen west table angry enact melody unusual logic denial smile major size life welcome bitter menu venue city own blur",
			},
			wantErr: false,
		},
		{
			name: "test#2",
			args: args{length: 12},
			want: &Account{
				Mnemonic: "sting business fog copy citizen west table angry enact melody unusual logic",
			},
			wantErr: false,
		},
		{

			name:    "test#3",
			args:    args{length: 1},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateMnemonicByLength(tt.args.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateMnemonicByLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && err != nil {
				return
			}
			mne := strings.Split(got.Mnemonic, " ")
			if len(mne) != tt.args.length {
				t.Errorf("ToAccount() got1 = %v, want_pk %v", len(mne), tt.args.length)
			}

		})
	}
}
