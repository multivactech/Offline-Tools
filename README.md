# MultiVAC离线使用工具

## 说明：

本项目适用于MultiVAC的离线工具，基于Go1.12版本，在离线下具有以下功能：

1. 随机生成适用于MultiVAC的私钥和对应的公钥(GenerateKeyByRandom)
2. 根据用户给的私钥生成对应的公钥(PrivateKeyToPublicKey)
3. 使用私钥对输入的交易进行签名(Signature)
4. 根据助记词生成私钥及其公钥
5. 将私钥保存到keystore
6. 根据（keystore+密码）或助记词找回私钥

## 使用方法：

根据源码编译好的二进制文件位于/MultiVACTools/application文件夹内，用户可以根据自己的操作系统选择符合自己系统运行的二进制文件。其中GenerateKeyByRandom、PrivateKeyToPublicKey、Signature这三个文件为旧版本的离线工具，没有助记词和keystore功能，main为新版本，新版和旧版在私钥、公钥和签名功能上完全兼容，两个版本完全互通，新版本的助记词功能和keystore功能在旧版上上无法使用，程序为命令行工具，打开工具根据提示输入编号即可，在输入编号时程序只会关注第一个输入的字符，所以在输入选择功能菜单的时候请确定您的输入是否正确。 

## 源码编译：

源码的主程序位于项目的Main目录下，项目需要的依赖已经放在了vendor目录下面，可以自行打开源码，在Go1.12以上版本进行编译。编译的时候跳转到Main目录下，在命令行（终端）输入：

```bash
go build main.go
```