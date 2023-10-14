package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	Data string `json:"data"`
	Pri  string `json:"pri"`
	Pub  string `json:"pub"`
	Sig  string `json:"sig"`
}

type Keys struct {
	Pri string `json:"pri"`
	Pub string `json:"pub"`
}

type Reply struct {
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

var (
	h    bool
	p    int
	host string
)

func sm2_load_key(pri, pub string) (sm2.PrivateKey, error) {
	if len(pri) != 64 || len(pub) != 128 {
		msg := "公私钥长度应该为128和64"
		return sm2.PrivateKey{}, fmt.Errorf(msg)
	}
	bytes_pub, e := hex.DecodeString(pub[0:64])
	if e != nil {
		msg := fmt.Sprintf("公钥参数错误: %s", e)
		return sm2.PrivateKey{}, fmt.Errorf(msg)
	}
	bytes_pri, e := hex.DecodeString(pri[0:64])
	if e != nil {
		msg := fmt.Sprintf("私钥参数错误: %s", e)
		return sm2.PrivateKey{}, fmt.Errorf(msg)
	}
	// pub
	pub_x := new(big.Int).SetBytes(bytes_pub)
	c := []byte{}
	c = append(c, 0x04)
	c = append(c, pub_x.Bytes()...)
	pubkey := sm2.Decompress(c)
	var pk sm2.PrivateKey
	pk.PublicKey.Curve = pubkey.Curve
	pk.PublicKey.X = pubkey.X
	pk.PublicKey.Y = pubkey.Y
	// pri
	pk.D = new(big.Int).SetBytes(bytes_pri)
	// check
	return pk, nil
}

func (gmsm *GMSM2) Sign(args Args, reply *Reply) error {
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_sign :%s", e)
		return fmt.Errorf(msg)
	}
	log.Println("Sign", string(data))
	pk, e := sm2_load_key(args.Pri, args.Pub)
	if e != nil {
		return e
	}
	out, e := pk.Sign(rand.Reader, data, nil)
	if e != nil {
		msg := fmt.Sprintf("sm2_sign :%s", e)
		return fmt.Errorf(msg)
	}
	reply.Msg = "ok"
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func (gmsm *GMSM2) Verify(args Args, reply *Reply) error {
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_verify :%s", e)
		return fmt.Errorf(msg)
	}
	sigout, e := base64.StdEncoding.DecodeString(args.Sig)
	if e != nil {
		msg := fmt.Sprintf("sm2_verify :%s", e)
		return fmt.Errorf(msg)
	}
	log.Println("Verify: ", string(data), " Sig: ", args.Sig)
	pk, e := sm2_load_key(args.Pri, args.Pub)
	if e != nil {
		return e
	}
	reply.Data = strconv.FormatBool(pk.PublicKey.Verify(data, sigout))
	reply.Msg = "ok"
	return nil
}

func (gmsm *GMSM2) Encrypt(args Args, reply *Reply) error {
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_encrypt :%s", e)
		return fmt.Errorf(msg)
	}
	log.Println("Encrypt", string(data))
	pk, e := sm2_load_key(args.Pri, args.Pub)
	if e != nil {
		return e
	}
	out, e := sm2.Encrypt(&pk.PublicKey, data, rand.Reader, 0)
	if e != nil {
		msg := fmt.Sprintf("sm2_encrypt :%s", e)
		return fmt.Errorf(msg)
	}
	reply.Msg = "ok"
	reply.Data = base64.StdEncoding.EncodeToString(out)
	return nil
}

func (gmsm *GMSM2) Decrypt(args Args, reply *Reply) error {
	data, e := base64.StdEncoding.DecodeString(args.Data)
	if e != nil {
		msg := fmt.Sprintf("sm2_decrypt :%s", e)
		return fmt.Errorf(msg)
	}
	log.Println("Decrypt", args.Data)
	pk, e := sm2_load_key(args.Pri, args.Pub)
	if e != nil {
		return e
	}
	out, e := sm2.Decrypt(&pk, data, 0)
	if e != nil {
		msg := fmt.Sprintf("sm2_decrypt :%s", e)
		return fmt.Errorf(msg)
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
