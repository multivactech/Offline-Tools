package Account

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func decode(pub string) []byte {
	res, _ := hex.DecodeString(pub)
	return res
}
func TestPrivatekeyToPublickey(t *testing.T) {
	type args struct {
		prv string
	}
	tests := []struct {
		name    string
		args    args
		want    PublicKey
		wantErr bool
	}{
		{
			name: "test#1",
			args: args{
				prv: "73bf138f570a5ff374fa024d1ef925e217598c9ab0b38631605a90b84a20ca52cc7f08c05db92f4ae3f290b04fdf81cea147f085533b9bdd2f11a095575de5c9",
			},
			want:    PublicKey(decode("cc7f08c05db92f4ae3f290b04fdf81cea147f085533b9bdd2f11a095575de5c9")),
			wantErr: false,
		},
		{
			name: "test#2",
			args: args{
				prv: "1940a11da864712c3bad3e1f71b78fd00ea093a522844ce7245240b36b9c13cd44f85f28bac82d53994b135eb537a00011de7ae840e062c19b2d6d89a3ed1cc2",
			},
			want:    PublicKey(decode("44f85f28bac82d53994b135eb537a00011de7ae840e062c19b2d6d89a3ed1cc2")),
			wantErr: false,
		},
		{
			name: "test#3",
			args: args{
				prv: "99c15275555075f60470227e7030d07bc5c132e3ef7c8d7b87621b1e671b7d20389758df61b89e5933496eb36124666e5209ab4d54dd036fff036dd4ac87b901",
			},
			want:    PublicKey(decode("389758df61b89e5933496eb36124666e5209ab4d54dd036fff036dd4ac87b901")),
			wantErr: false,
		},
		{
			name: "test#4",
			args: args{
				prv: "2023213a52e26e871750af5b6afb69441df019a4316377001af89753445ace8192b7e5c910752e3ca1ac40c7a67fc349a4e057d70428ace21d8edff93527fa1f",
			},
			want:    PublicKey(decode("92b7e5c910752e3ca1ac40c7a67fc349a4e057d70428ace21d8edff93527fa1f")),
			wantErr: false,
		},
		{
			name: "test#5",
			args: args{
				prv: "50f288267c3c0da11c591ea1acdff4f6b4580586e043e09aee8ebf9e2d8b2b272f12e4684c79f41b5137bc8def2cc081a20d1b2b84c1c277da9ecd39c9104339",
			},
			want:    PublicKey(decode("2f12e4684c79f41b5137bc8def2cc081a20d1b2b84c1c277da9ecd39c9104339")),
			wantErr: false,
		},
		{
			name: "error#1",
			args: args{
				prv: "50f288267c3c0da11c591ea1acdff4f6b4580586e043e09aee8ebf9e2d8b2b272f12e4684c79f41b5137bc8def2cc081a20d1b2b84c1c277da9ecd39c910433",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error#2",
			args: args{
				prv: "50f288267c3c0da11c591ea1acdff4f6b4580586e043e09aee8ebf9e2d8b2b272f12e468kk79f41b5137bc8def2cc081a20d1b2b84c1c277da9ecd39c9104339",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PrivatekeyToPublickey(tt.args.prv)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivatekeyToPublickey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PrivatekeyToPublickey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
