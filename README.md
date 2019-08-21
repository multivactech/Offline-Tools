# MultiVAC离线使用工具

## 说明：

本项目适用于MultiVAC的离线工具，基于Go1.12版本，在离线下具有以下功能：

1. 随机生成适用于MultiVAC的私钥和对应的公钥(GenerateByRandom)
2. 根据用户给的私钥生成对应的公钥(GenerateByPrivateKey)
3. 使用私钥对输入的交易进行签名(Signature)

## 使用方法：

根据源码编译好的二进制文件位于/MultiVACTools/application文件夹内，用户可以根据自己的操作系统选择符合自己系统运行的二进制文件。

## 源码编译：

源码的三个工具分别对应了三个文件夹，项目需要的依赖已经放在了vender目录下面，可以自行打开源码，在Go1.12以上版本进行编译。