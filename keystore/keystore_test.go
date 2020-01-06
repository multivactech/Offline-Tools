package keystore

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func decode64(str string) []byte {
	data, _ := base64.StdEncoding.DecodeString(str)
	return data
}

var k1 = JSON{
	Kdfparam: &KdfParam{
		N:      32768,
		R:      8,
		P:      1,
		KeyLen: 32,
		Salt:   decode64("TXVsdGlWQUM="),
	},
	CipherParams: CipherParams{
		Iv: decode64("MTIzNDU2NzhNdWx0aVZBQw=="),
	},
	Cipher:     "aes-128-ctr",
	CipherText: decode64("vHyOFGj7JJ9JO6CWIRmz5FLncHI3SDzVw8bAo9r/cGKEHsiQITDp/4SuV/H3XbTQiLXQ3DILnpnHSvblc/b/qtXhP+jHLZ0HcJwk2dDwx47+k9gg5T1xm1QGAvY408BxGUF8sN3wlq+gqMUCf1AKHVa0+uTBklgy6ITyBfYZL4s="),
	Kdf:        "PBKDF2",
	Mac:        decode64("xNw2ArTDxNRAaGrqHZXLwFty0SHdvx52NlHxMUh+95o="),
	Version:    "1.0",
	Project:    "MultiVAC",
}
var k2 = JSON{
	Kdfparam: &KdfParam{
		N:      32768,
		R:      8,
		P:      1,
		KeyLen: 32,
		Salt:   decode64("TXVsdGlWQUM="),
	},
	CipherParams: CipherParams{
		Iv: decode64("MTIzNDU2NzhNdWx0aVZBQw=="),
	},
	Cipher:     "aes-128-ctr",
	CipherText: decode64("vy/aTz6keJhJPPLEIUbn5wTmcyBsQj2BzMeSpN7+ImuDEZnCdGfp/oClX62lUeeKgOTRiWNem5rLTa3uL6aq+NW0YuvGKctbKZx239ahzd6owYsnsTwjlVVbBqk/hMsoGhgosd2ilfugqcBWfQAKTgy0rOWXkQJlvNSpCPFEf9I="),
	Kdf:        "PBKDF2",
	Mac:        decode64("Cy0rYsm2V3nE4J0Bbv58muPOfAj2S6tr05sDDPG5Guo="),
	Version:    "1.0",
	Project:    "MultiVAC",
}

func TestCreateKeyStore(t *testing.T) {
	type args struct {
		password   []byte
		privateKey []byte
	}
	tests := []struct {
		name    string
		args    args
		want    JSON
		wantErr bool
	}{
		{
			name: "test#1",
			args: args{
				password:   []byte("multivacTest"),
				privateKey: []byte("31e8f9d27aaa9fc0fc1b936f941a44d8b7514392a988a5c81a277b0585b99e3b84e19ae882bc3f252b2716b75e69e39a1a0c2f0650022a2d892b5ebc6cc87d18"),
			},
			want:    k1,
			wantErr: false,
		},
		{
			name: "test#2",
			args: args{
				password:   []byte("multivacTest"),
				privateKey: []byte("0b1c0f857f3399730b20b97265cf0561e8dcad93e20d390b903bf7564292e5f08a828e3da20e578ed0a0e709482fbd2828db243b515f0127b9dccf84b38509aa"),
			},
			want:    k2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateKeyStore(tt.args.password, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKeyStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateKeyStore() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPrivatekeyFromKeystore(t *testing.T) {
	type args struct {
		password string
		keystore JSON
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test#1",
			args: args{
				password: "multivacTest",
				keystore: k1,
			},
			want:    "31e8f9d27aaa9fc0fc1b936f941a44d8b7514392a988a5c81a277b0585b99e3b84e19ae882bc3f252b2716b75e69e39a1a0c2f0650022a2d892b5ebc6cc87d18",
			wantErr: false,
		}, {
			name: "test#2",
			args: args{
				password: "multivacTest",
				keystore: k2,
			},
			want:    "0b1c0f857f3399730b20b97265cf0561e8dcad93e20d390b903bf7564292e5f08a828e3da20e578ed0a0e709482fbd2828db243b515f0127b9dccf84b38509aa",
			wantErr: false,
		}, {
			// password is error.
			name: "error#1",
			args: args{
				password: "multivac",
				keystore: k2,
			},
			want:    "",
			wantErr: true,
		}, {
			// CipherText is error.
			name: "error#2",
			args: args{
				password: "multivacTest",
				keystore: JSON{
					Kdfparam: &KdfParam{
						N:      32768,
						R:      8,
						P:      1,
						KeyLen: 32,
						Salt:   decode64("TXVsdGlWQUM="),
					},
					CipherParams: CipherParams{
						Iv: decode64("MTIzNDU2NzhNdWx0aVZBQw=="),
					},
					Cipher:     "aes-128-ctr",
					CipherText: decode64("vy/aTzwTmcyBsQj2BzMeSpN7+ImuDEZnCdGfp/oCGKctbKZx239ahzd6owYsnsTwjlVVbBqk/hMsoGhgosd2ilfugqcBWfQAKTgy0rOWXkQJlvNSpCPFEf9I="),
					Kdf:        "PBKDF2",
					Mac:        decode64("Cy0rYsm2V3nE4J0Bbv58muPOfAj2S6tr05sDDPG5Guo="),
					Version:    "1.0",
					Project:    "MultiVAC",
				},
			},
			want:    "",
			wantErr: true,
		}, {
			// mac is error.
			name: "error#3",
			args: args{
				password: "multivacTest",
				keystore: JSON{
					Kdfparam: &KdfParam{
						N:      32768,
						R:      8,
						P:      1,
						KeyLen: 32,
						Salt:   decode64("TXVsdGlWQUM="),
					},
					CipherParams: CipherParams{
						Iv: decode64("MTIzNDU2NzhNdWx0aVZBQw=="),
					},
					Cipher:     "aes-128-ctr",
					CipherText: decode64("vy/aTz6keJhJPPLEIUbn5wTmcyBsQj2BzMeSpN7+ImuDEZnCdGfp/oClX62lUeeKgOTRiWNem5rLTa3uL6aq+NW0YuvGKctbKZx239ahzd6owYsnsTwjlVVbBqk/hMsoGhgosd2ilfugqcBWfQAKTgy0rOWXkQJlvNSpCPFEf9I="),
					Kdf:        "PBKDF2",
					Mac:        decode64("Cyr05sDDPG5Guo="),
					Version:    "1.0",
					Project:    "MultiVAC",
				},
			},
			want:    "",
			wantErr: true,
		}, {
			// kdf param is error.
			name: "error#4",
			args: args{
				password: "multivacTest",
				keystore: JSON{
					Kdfparam: &KdfParam{
						N:      328,
						R:      8,
						P:      1,
						KeyLen: 32,
						Salt:   decode64("TXVsdGlWQUM="),
					},
					CipherParams: CipherParams{
						Iv: decode64("MTIzNDU2NzhNdWx0aVZBQw=="),
					},
					Cipher:     "aes-128-ctr",
					CipherText: decode64("vy/aTz6keJhJPPLEIUbn5wTmcyBsQj2BzMeSpN7+ImuDEZnCdGfp/oClX62lUeeKgOTRiWNem5rLTa3uL6aq+NW0YuvGKctbKZx239ahzd6owYsnsTwjlVVbBqk/hMsoGhgosd2ilfugqcBWfQAKTgy0rOWXkQJlvNSpCPFEf9I="),
					Kdf:        "PBKDF2",
					Mac:        decode64("Cyr05sDDPG5Guo="),
					Version:    "1.0",
					Project:    "MultiVAC",
				},
			},
			want:    "",
			wantErr: true,
		}, {
			// cipher param is error.
			name: "error#5",
			args: args{
				password: "multivacTest",
				keystore: JSON{
					Kdfparam: &KdfParam{
						N:      32768,
						R:      8,
						P:      1,
						KeyLen: 32,
						Salt:   decode64("TXVsdGlWQUM="),
					},
					CipherParams: CipherParams{
						Iv: decode64("MTU2NzhNdWx0aVZBQw=="),
					},
					Cipher:     "aes-128-ctr",
					CipherText: decode64("vy/aTz6keJhJPPLEIUbn5wTmcyBsQj2BzMeSpN7+ImuDEZnCdGfp/oClX62lUeeKgOTRiWNem5rLTa3uL6aq+NW0YuvGKctbKZx239ahzd6owYsnsTwjlVVbBqk/hMsoGhgosd2ilfugqcBWfQAKTgy0rOWXkQJlvNSpCPFEf9I="),
					Kdf:        "PBKDF2",
					Mac:        decode64("Cyr05sDDPG5Guo="),
					Version:    "1.0",
					Project:    "MultiVAC",
				},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPrivatekeyFromKeystore(tt.args.password, tt.args.keystore)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPrivatekeyFromKeystore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetPrivatekeyFromKeystore() got = %v, want %v", got, tt.want)
			}
		})
	}
}
