# MultiVAC离线使用工具

## 说明：

本项目适用于MultiVAC的离线工具，基于Go1.12版本，在离线环境下具有以下功能：

1. 生成MultiVAC账户，包括:私钥、公钥，助记词和keystore。
2. 使用私钥对输入的交易进行签名(Signature)。
3. 根据助记词、keystore找回私钥。

## 安装&编译：

```
git clone https://github.com/multivactech/Offline-Tools.git

go build -o tool

```

## 使用：

```
./tool -h
可以看到可执行子命令的操作

./tool
          recover
                bykeystore  [keystore路径] [keystore密码]（注：此密码为之前此账户设置的密码） //根据keystore恢复私钥
                bymnemonic  [助记词]                                   //根据助记词恢复私钥
          generate  [keystore密码] （注：此密码为新设置的密码，请妥善保存）   //根据密码返回：公钥，私钥，助记词，keysotre本地文件       
          sign    [私钥名称] [签名信息]                                  //根据私钥对某个签名信息进行签名，返回一个签名完成的信息
          version                                                     //返回当前离线工具版本信息
```

## 用例：

### 根据keystore恢复私钥
```
input：
./tool recover bykeystore MultiVACkeystore/MultiVAC2020-1-3-11-34-29.json 123

output：
private key: 189a62ca1b59ce5d8bbf539216e0aa5fb9b956749d10e9cfe8623826484a1388de34cd10d92ec8908da538fec38409f920e5011132cddc048212ee95a7c177d6
```
### 根据助记词恢复私钥
```
input：
./tool recover bymnemonic pig roof metal receive fiber script dash aspect deny submit orchard prosper narrow reflect hood witness cherry friend smooth come smooth identify wrestle include

output：
public key: de34cd10d92ec8908da538fec38409f920e5011132cddc048212ee95a7c177d6
private key: 189a62ca1b59ce5d8bbf539216e0aa5fb9b956749d10e9cfe8623826484a1388de34cd10d92ec8908da538fec38409f920e5011132cddc048212ee95a7c177d6
```
### 生成账户
注：keystore文件生成在当前二进制运行目录下，生成keystore时会打印出生成的路径和文件名：
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

### 签名
```
input:
./tool sign 9e8b8417f97743fbadc2b8a37905858d7b67bb376893362c142f4e280f70587d01619e1a8a4b15d0bbf9d8fc210773219279033b771f36e3d833514b2eb1c8df f8f682010180f881f87ff87d80a0c43a42b737e9b9dccdfd33239394f430833dca6a13a217b6f667c647eff031de80a54d5456314c656e35326b367a424d446b577573614b6a6944395a6b6958636242564872736a068dcc8b52b7d2dcc80cd2e4000000a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636887472616e73666572b2f1a54d5456313969705346716e315179576b4858396e6369315352563135767833345555336e5202893635c9adc5dea000008080808089746573747261777478.a56924309a5f37ff24d7ddddc2aad6d5537a757652341a6541171fd1365ea5fa.123

output:
sign success! message is: f8f682010180f881f87ff87d80a0c43a42b737e9b9dccdfd33239394f430833dca6a13a217b6f667c647eff031de80a54d5456314c656e35326b367a424d446b577573614b6a6944395a6b6958636242564872736a068dcc8b52b7d2dcc80cd2e4000000a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636a44d5456514c627a374a48694254737053393632524c4b5638476e645746776a41354b3636887472616e73666572b2f1a54d5456313969705346716e315179576b4858396e6369315352563135767833345555336e5202893635c9adc5dea000008080808089746573747261777478.c4444cae7213b006b4660b90f54fc749fc33e4e797c01d8d10582b68cae90baa62c7a9cf9b50136a1a765cb0f2611a8328ba444515157a1a729640e5c1239b0f.01619e1a8a4b15d0bbf9d8fc210773219279033b771f36e3d833514b2eb1c8df
```

## 注意事项：

1. 助记词和私钥具有等同地位，助记词泄漏意味着私钥泄漏，所以务必保存好助记词，不要让他人知晓。
2. keystore的密码请务必记清楚，里面的内容请不要修改，否则无法保证从keystore中找回私钥。
3. 本项目支持windows平台，在windows平台运行时不加`"./"`（ `./tool` ======> `tool`）
