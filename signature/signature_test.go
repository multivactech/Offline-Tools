package signature

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSign(t *testing.T) {
	ans1, _ := hex.DecodeString("20f8d451cc80eeadafa8c8a1fe4210fb1af8b745cb07b03a2037590b3c637fed0b8f6641d73120ddee6974989f7ddcd39ab6b0932955befea06f11f950041f00")
	ans2, _ := hex.DecodeString("ec77092c24383188c73399b3d678f5b6eee55d2c3c99db443cc896e73620275555c2fd4a07d189db624e0352b517926a5d64694c8688c6aa8e0fa740391a790c")
	type args struct {
		privateKey string
		message    []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "test#1",
			args: args{
				privateKey: "a1b6d9772dfb72b4bd547fa38ece539668c95c681fb42f4cc79387ef729c935c20f9715d2135b756af61d8a1e8330badc21d76673b24c64e641b43104b46ebd9",
				message:    []byte("4cc79387ef729c935c20f9715d2135b756af61d8a1e8330badc21d7667"),
			},
			want:    ans1,
			wantErr: false,
		},
		{
			name: "test#1",
			args: args{
				privateKey: "118a49e8cddf0d313750b15f1b5f6bad205c621138b2a678ec9a8262d3d1691d44c430f07e187e5d9d9fd22a57f0cb7065f02b76a76cc3085802b85954f4c14f",
				message:    []byte("4cc79387ef729c935c20f9715d2135b756af61d8a1e8330badc21d7667"),
			},
			want:    ans2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sign(tt.args.privateKey, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign() got = %v, want %v", got, tt.want)
			}
		})
	}
}
