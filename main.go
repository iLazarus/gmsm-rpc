package main

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
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
	Data string `json:"data"`
	Sig  string `json:"sig"`
}

type Reply struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

func sm2_load_key(pri string, pub string) {
	bytes_pub, e := hex.DecodeString(pub[0:64])
	if e != nil {
		log.Fatal("sm2_load_key pub key err: ", e)
	}
	pub_x := new(big.Int).SetBytes(bytes_pub)
	c := []byte{}
	c = append(c, 0x04)
	c = append(c, pub_x.Bytes()...)
	pubkey := sm2.Decompress(c)
	priv.PublicKey.Curve = pubkey.Curve
	priv.PublicKey.X = pubkey.X
	priv.PublicKey.Y = pubkey.Y
	pribytes, e := hex.DecodeString(pri[0:64])
	if e != nil {
		log.Fatal("sm2_load_key pri key err: ", e)
	}
	priv.D = new(big.Int).SetBytes(pribytes)
	log.Println("公私钥初始化成功")
}

func (gmsm *GMSM2) Sign(args Args, reply *Reply) error {
	log.Println("Sign", args.Data)
	msg := "ok"
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg = fmt.Sprintf("sm2_sign base64 decode err:%s", e)
		return fmt.Errorf(msg)
	}
	out, e := priv.Sign(rand.Reader, data, nil)
	if e != nil {
		msg = fmt.Sprintf("sm2_sign private key sign err:%s", e)
		return fmt.Errorf(msg)
	}
	reply.Msg = msg
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func (gmsm *GMSM2) Verify(args Args, reply *Reply) error {
	log.Println("Verify Data:", args.Data, "Sig:", args.Sig)
	msg := "ok"
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg = fmt.Sprintf("sm2_verify data base64 decode err:%s", e)
		return fmt.Errorf(msg)
	}
	sigout, e := base64.StdEncoding.DecodeString(args.Sig)
	if e != nil {
		msg = fmt.Sprintf("sm2_verify sig base64 decode err:%s", e)
		return fmt.Errorf(msg)
	}
	reply.Msg = msg
	if priv.PublicKey.Verify(data, sigout) {
		reply.Data = "true"
	} else {
		reply.Data = "false"
	}
	return nil
}

func (gmsm *GMSM2) Encrypt(args Args, reply *Reply) error {
	log.Println("Encrypt", args.Data)
	msg := "ok"
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg = fmt.Sprintf("sm2_encrypt data base64 decode err:%s", e)
		return fmt.Errorf(msg)
	}
	out, e := sm2.Encrypt(&priv.PublicKey, data, rand.Reader, 0)
	if e != nil {
		msg = fmt.Sprintf("sm2_encrypt data encrypt err:%s", e)
		return fmt.Errorf(msg)
	}
	reply.Msg = msg
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func (gmsm *GMSM2) Decrypt(args Args, reply *Reply) error {
	log.Println("Decrypt", args.Data)
	msg := "ok"
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg = fmt.Sprintf("sm2_decrypt data base64 decode err:%s", e)
		return fmt.Errorf(msg)
	}
	out, e := sm2.Decrypt(&priv, data, 0)
	if e != nil {
		msg = fmt.Sprintf("sm2_decrypt data decrypt err:%s", e)
		return fmt.Errorf(msg)
	}
	reply.Msg = msg
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

var (
	priv sm2.PrivateKey
	h    bool
	p    int
	k    string
	pri  string
	pub  string
	host string
)

func init() {
	flag.BoolVar(&h, "h", false, "帮助")
	flag.IntVar(&p, "p", 50001, "默认RPC端口")
	flag.StringVar(&k, "k", "", "默认key文件路径")
	flag.StringVar(&pri, "pri", "", "私钥hex")
	flag.StringVar(&pub, "pub", "", "公钥hex")
	flag.StringVar(&host, "host", "127.0.0.1", "默认监听ip")
}

func main() {

	flag.Parse()
	if h {
		flag.Usage()
	}
	if k == "" && (pri == "" || pub == "") {
		log.Fatal("必须指定私钥文件路径或使用公私钥匙")
	}
	if len(pri) >= 64 && len(pub) >= 64 {
		log.Println("使用用户提供的公私钥")
	} else {
		log.Println("使用私钥文件解析密钥")
		f, e := ioutil.ReadFile(k)
		if e != nil {
			log.Fatal(k, "私钥读取失败", e)
		}
		b64, e := base64.StdEncoding.DecodeString(string(f))
		if e != nil {
			log.Fatal(k, "私钥内容不是base64编码的数据", e)
		}
		var pk asn1.RawValue
		asn1.Unmarshal(b64, &pk)
		secrt := hex.EncodeToString(pk.FullBytes[8:40])
		X := hex.EncodeToString(pk.FullBytes[58 : 58+32])
		Y := hex.EncodeToString(pk.FullBytes[58+32 : 58+64])
		log.Println(k, "密钥信息\n私钥 :", secrt, "\n公钥X:", X, "\n公钥Y:", Y)
		pri = secrt
		pub = X + Y
	}
	sm2_load_key(pri, pub)
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
