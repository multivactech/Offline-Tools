# keystore

### 简介：

keystore用于使用密码对私钥进行加密存储，解密获取私钥时需要提供密码

### 加密

```go
filename, _ := keystore.MakeKeyStore(pass, []byte(privatekey))
```

程序会在项目文件夹下生成一个json文件，文件名为filename

### 解密

```go
ciphertext, params, _ := keystore.ReadJson(filename)
prv2, _ := keystore.GetPrivatekeyFromKeystore(string(pass), params, ciphertext)
```

程序从本地进行json文件读取，然后根据用户的密码即可解密获得到用户的私钥