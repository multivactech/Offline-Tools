# MultiVAC Offline Tools
[![Go Report Card](https://goreportcard.com/badge/github.com/multivactech/Offline-Tools)](https://goreportcard.com/report/github.com/multivactech/Offline-Tools)  &ensp;     [![Build Status](https://travis-ci.org/multivactech/Offline-Tools.svg?branch=master)](https://travis-ci.org/multivactech/Offline-Tools) &ensp; [![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)  &ensp; ![GitHub](https://img.shields.io/github/license/multivactech/Offline-tools)

## Introduction：

The offline tools of MultiVAC can support the following functions in Go 1.12 version:

1. Create MultiVAC account, including: private key, public key, mnemonic seed, and keystore.
2. Use private key to make signature of a transaction.
3. Use mnemonic seed or keystore to retrieve private key.


## Install & Compile：

```
git clone https://github.com/multivactech/Offline-Tools.git

go build -o tool

```

## Use：

```
./tool -h
Check executable subcommand        
./tool
├── generate [keystore password] （Notes: this password is the newly set one. Please keep it safe）                 //By password return: public key, private key, mnemonic seed, keystore local file
├── recover
│   ├── bykeystore [keystore Path] [keystore Password]（Notes: this password was set for the account previously）   //Use keystore to retrieve private key
│   └── bymnemonic [mnemonic phrases]                                                                              //Use mnemonic phrases to retrieve private key
├── sign [private key] [signature info]                                                                            //Using private key to make signature and return a signature complete info
└── version                                                                                                        //return the current offline tool version info
```

## Example:

### Generate a new account
Note: keystore file is created in the current binary directory. Create keystore will print creation path and file name.
```
input:
./tool generate 123

output:
generate success!
public key: 44f3999d890d156ba8d239d6b0447a4c249423e0d46b148a8aa514eaf5e1d0c5
private key: ccf0f82e13429c71f8ebbf2a0929f4fe5df4061eb2e005550d3daed23c3b9fa744f3999d890d156ba8d239d6b0447a4c249423e0d46b148a8aa514eaf5e1d0c5
mnemonic: spoon glimpse act track hurt between nasty april ranch economy marble absorb van organ safe south mind urge base treat grant protect ski net
keystore file: /MultiVACkeystore/MultiVAC2020-1-3-11-27-44.json
```
### Recover private key with keystore
```
input：
./tool recover bykeystore MultiVACkeystore/MultiVAC2020-1-3-11-34-29.json 123

output：
private key: 189a62ca1b59ce5d8bbf539216e0aa5fb9b956749d10e9cfe8623826484a1388de34cd10d92ec8908da538fec38409f920e5011132cddc048212ee95a7c177d6
```
### Recover private key with mnemonic phrases
```
input：
./tool recover bymnemonic pig roof metal receive fiber script dash aspect deny submit orchard prosper narrow reflect hood witness cherry friend smooth come smooth identify wrestle include

output：
public key: de34cd10d92ec8908da538fec38409f920e5011132cddc048212ee95a7c177d6
private key: 189a62ca1b59ce5d8bbf539216e0aa5fb9b956749d10e9cfe8623826484a1388de34cd10d92ec8908da538fec38409f920e5011132cddc048212ee95a7c177d6
```

### Signature
```
input:
./tool sign 9e8b8417f97743fbadc2b8a37905858d7b67bb376893362c142f4e280f70587d01619e1a8a4b15d0bbf9d8fc210773219279033b771f36e3d833514b2eb1c8df f8f682010180f881f87ff87d80a0c43a42b737e9b9dccdfd33239394f430833dca6a13a217b6f667c647eff031de80a54d5456314c656e35326b367a424d446b577573614b6a6944395a6b6958636242564872736a068dcc8b52b7d2dcc80cd2e4000000a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636887472616e73666572b2f1a54d5456313969705346716e315179576b4858396e6369315352563135767833345555336e5202893635c9adc5dea000008080808089746573747261777478.a56924309a5f37ff24d7ddddc2aad6d5537a757652341a6541171fd1365ea5fa.123

output:
sign success! message is: f8f682010180f881f87ff87d80a0c43a42b737e9b9dccdfd33239394f430833dca6a13a217b6f667c647eff031de80a54d5456314c656e35326b367a424d446b577573614b6a6944395a6b6958636242564872736a068dcc8b52b7d2dcc80cd2e4000000a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636887472616e73666572b2f1a54d5456313969705346716e315179576b4858396e6369315352563135767833345555336e5202893635c9adc5dea000008080808089746573747261777478.c4444cae7213b006b4660b90f54fc749fc33e4e797c01d8d10582b68cae90baa62c7a9cf9b50136a1a765cb0f2611a8328ba444515157a1a729640e5c1239b0f.01619e1a8a4b15d0bbf9d8fc210773219279033b771f36e3d833514b2eb1c8df
```

## Notice:：

1. Mnemonic seed is equal to private key. If mnemonic seed is known, so is the private key. Please keep your mnemonic seed safe and confidential.
2. Please remember the info in keystore password. Please don’t modify any information or you can not use keystore to recover private key.
3. These tools support Windows operation system. Don’t add `"./"` on windows platform.（ `./tool` ======> `tool`）
