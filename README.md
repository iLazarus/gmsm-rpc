# gmsm-rpc
php jsonrpc call gmsm demo

php5.6不方便生成php扩展，退而求其次，使用RPC调用，

当然还有java版本，但考虑到部署复杂度，

又或者如C/C++等版本的开发复杂度，go方便太多
___
# 安装
```
git clone https://github.com/iLazarus/gmsm-rpc.git 
go get github.com/iLazarus/gmsm-rpc
go install
```

# 编译

**windows**

```
GOOS=windows GOARCH=amd64 go build -o gmsm.exe
```

**linux**

```
GOOS=linux GOARCH=amd64 go build -o gmsm
```

**help**

  -h    帮助
  
  -host string
        默认监听ip (default "127.0.0.1")
        
  -k string
        默认key文件路径
        
  -p int
        默认RPC端口 (default 50001)
        
  -pri string
        私钥hex
        
  -pub string
        公钥hex
        
  [-k]和 [-pri -pub] 二选一， [-pri -pub]参数优先级更高
        
