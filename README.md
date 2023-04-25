# gmsm-rpc
php jsonrpc call gmsm demo

**windows **
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
        
