# GenerateKeyByRandom

### 使用说明：

打开程序时程序会自动根据算法生成一个能够在MultiVAC上使用的私钥及对应的公钥，请妥善保管好生成的私钥，如果出现错误，请重新打开软件即可。

### 代码生成二进制文件：

在终端中将目录跳转至：MultiVACTools/GenerateKeyByRandom目录

然后在终端中输入以下代码：
```
go build GenerateKeyByRandom.go 
```
输入代码编译通过即可在目录下得到一个可以直接运行的二进制代码，然后双击该文件即可运行