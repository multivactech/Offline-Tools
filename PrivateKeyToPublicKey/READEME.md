# PrivateKeyToPublicKey

### 使用说明：

程序会根据输入的私钥使用ED25519算法生成私钥对应的公钥，打开程序后会有提示输入私钥，此时输入私钥然后键入“Enter”键即可得到私钥对应的公钥，请务必保证私钥的私密性！

注意：如果输入的私钥有问题，程序会显示错误并直接退出

### 代码生成二进制文件：

在终端中将目录跳转至：MultiVACTools/PrivateKeyToPublicKey目录

然后在终端中输入以下代码：
```
go build PrivateKeyToPublicKey.go 
```
输入代码编译通过即可在目录下得到一个可以直接运行的二进制代码，然后双击该文件即可运行