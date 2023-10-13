package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strconv"

	"github.com/tjfoc/gmsm/sm2"
)

type GMSM2 struct {
}

type Args struct {
	Index string `json:index`
	Data  string `json:"data"`
	Sig   string `json:"sig"`
}

type Keys struct {
	Index string `json:index`
	Pri   string `json:"pri"`
	Pub   string `json:"pub"`
}

type Reply struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

var (
	priv map[string]sm2.PrivateKey
	h    bool
	p    int
	host string
)

func sm2_load_key(index, pri, pub string) error {
	bytes_pub, e := hex.DecodeString(pub[0:64])
	if e != nil {
		msg := fmt.Sprintf("公钥参数错误: %s", e)
		return fmt.Errorf(msg)
	}
	pub_x := new(big.Int).SetBytes(bytes_pub)
	c := []byte{}
	c = append(c, 0x04)
	c = append(c, pub_x.Bytes()...)
	pubkey := sm2.Decompress(c)

	pk, ok := priv[index]
	if ok {
		msg := "index已存在"
		return fmt.Errorf(msg)
	}
	pk.PublicKey.Curve = pubkey.Curve
	pk.PublicKey.X = pubkey.X
	pk.PublicKey.Y = pubkey.Y
	pribytes, e := hex.DecodeString(pri[0:64])
	if e != nil {
		msg := fmt.Sprintf("私钥参数长度错误: %s", e)
		return fmt.Errorf(msg)
	}
	pk.D = new(big.Int).SetBytes(pribytes)

	sign, err := pk.Sign(rand.Reader, []byte("testInit123456"), nil)
	if err != nil {
		msg := fmt.Sprintf("私钥参数错误: %s", e)
		return fmt.Errorf(msg)
	}
	if pk.PublicKey.Verify([]byte("testInit123456"), sign) {
		priv[index] = pk
	} else {
		msg := "密钥无法正常通过校验"
		return fmt.Errorf(msg)
	}
	return nil
}

func (gmsm *GMSM2) Init(args Args, reply *Reply) error {
	log.Println("Init", args.Data)
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("Init参数错误:%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	log.Println("Init", string(data))
	var keys Keys
	if e := json.Unmarshal(data, &keys); e != nil {
		msg := fmt.Sprintf("Init参数错误:%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	if (keys.Pri == "" || keys.Pub == "") && keys.Index == "" {
		msg := "Init参数错误 data中没有正确的字段"
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	if len(keys.Pri) >= 64 && len(keys.Pub) >= 128 {
		log.Println("使用用户提供的公私钥")
	}
	if e := sm2_load_key(keys.Index, keys.Pri, keys.Pub); e != nil {
		msg := fmt.Sprintf("Init初始化失败 %s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	reply.Msg = "Init初始化成功"
	reply.Data = keys.Index
	return nil
}

func (gmsm *GMSM2) Sign(args Args, reply *Reply) error {
	log.Println("Sign", args.Data)
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_sign :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	pk, ok := priv[args.Index]
	if !ok {
		msg := "index不存在，请先初始化"
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	out, e := pk.Sign(rand.Reader, data, nil)
	if e != nil {
		msg := fmt.Sprintf("sm2_sign :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	reply.Msg = "ok"
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func (gmsm *GMSM2) Verify(args Args, reply *Reply) error {
	log.Println("Verify Data:", args.Data, "Sig:", args.Sig)
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_verify :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	sigout, e := base64.StdEncoding.DecodeString(args.Sig)
	if e != nil {
		msg := fmt.Sprintf("sm2_verify :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	pk, ok := priv[args.Index]
	if !ok {
		msg := "index不存在，请先初始化"
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	if pk.PublicKey.Verify(data, sigout) {
		reply.Data = "true"
	} else {
		reply.Data = "false"
	}
	reply.Msg = "ok"
	return nil
}

func (gmsm *GMSM2) Encrypt(args Args, reply *Reply) error {
	log.Println("Encrypt", args.Data)
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_encrypt :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	pk, ok := priv[args.Index]
	if !ok {
		msg := "index不存在，请先初始化"
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	out, e := sm2.Encrypt(&pk.PublicKey, data, rand.Reader, 0)
	if e != nil {
		msg := fmt.Sprintf("sm2_encrypt :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	reply.Msg = "ok"
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func (gmsm *GMSM2) Decrypt(args Args, reply *Reply) error {
	log.Println("Decrypt", args.Data)
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_decrypt :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	pk, ok := priv[args.Index]
	if !ok {
		msg := "index不存在，请先初始化"
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	out, e := sm2.Decrypt(&pk, data, 0)
	if e != nil {
		msg := fmt.Sprintf("sm2_decrypt :%s", e)
		reply.Msg = msg
		reply.Data = ""
		return nil
	}
	reply.Msg = "ok"
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func init() {
	flag.BoolVar(&h, "h", false, "帮助")
	flag.IntVar(&p, "p", 50001, "默认RPC端口")
	flag.StringVar(&host, "host", "127.0.0.1", "默认监听ip")
}

func main() {

	// log.Println("使用私钥文件解析密钥")
	// f, e := os.ReadFile("./1.key")
	// if e != nil {
	// 	log.Fatal("私钥读取失败", e)
	// }
	// b64, e := base64.StdEncoding.DecodeString(string(f))
	// if e != nil {
	// 	log.Fatal("私钥内容不是base64编码的数据", e)
	// }
	// var pk asn1.RawValue
	// asn1.Unmarshal(b64, &pk)
	// secrt := hex.EncodeToString(pk.FullBytes[8:40])
	// X := hex.EncodeToString(pk.FullBytes[58 : 58+32])
	// Y := hex.EncodeToString(pk.FullBytes[58+32 : 58+64])
	// log.Println("密钥信息\n私钥 :", secrt, "\n公钥X:", X, "\n公钥Y:", Y)
	// log.Println(secrt)
	// log.Println(X + Y)

	flag.Parse()
	if h {
		flag.Usage()
	}
	priv = make(map[string]sm2.PrivateKey)
	rpc.Register(new(GMSM2))
	port := host + ":" + strconv.Itoa(p)
	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatal("启动失败", err)
	}
	log.Println("RPC启动于", port)
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("RPC错误: ", err)
			continue
		}
		log.Printf("\n\nRPC comming from:%s\n", conn.RemoteAddr())
		go jsonrpc.ServeConn(conn)
	}
}
