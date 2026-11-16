// spa-client 发送一个带签名的 UDP 授权包到服务端。
//
// 用法:
//
//	spa-client -server 1.2.3.4:62201 -user alice -key <hex> -port 22 -duration 120
//	spa-client -genkey   # 生成一个新用户密钥
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"spa/internal/spa"
)

func main() {
	server := flag.String("server", "", "服务端地址 host:port")
	user := flag.String("user", "", "用户 ID")
	keyHex := flag.String("key", "", "用户密钥(hex)")
	port := flag.Int("port", 22, "请求放开的端口")
	duration := flag.Int("duration", 60, "请求放开的秒数(服务端会钳制上限)")
	genkey := flag.Bool("genkey", false, "生成一个随机密钥并退出")
	// 以下两个参数仅用于测试(重放/过期包), 正常使用不要设置。
	tsOverride := flag.Int64("ts", 0, "覆盖时间戳(测试用)")
	nonceHex := flag.String("nonce", "", "覆盖 nonce(hex, 测试用)")
	flag.Parse()

	if *genkey {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	}
	if *server == "" || *user == "" || *keyHex == "" {
		fmt.Fprintln(os.Stderr, "必须指定 -server -user -key (或用 -genkey 生成密钥)")
		flag.Usage()
		os.Exit(2)
	}

	key, err := hex.DecodeString(*keyHex)
	if err != nil || len(key) == 0 {
		log.Fatalf("无效的密钥: %v", err)
	}

	pkt := &spa.Packet{
		UserID:    *user,
		Timestamp: time.Now().Unix(),
		Port:      uint16(*port),
		Duration:  uint32(*duration),
	}
	if _, err := rand.Read(pkt.Nonce[:]); err != nil {
		log.Fatal(err)
	}
	if *tsOverride != 0 {
		pkt.Timestamp = *tsOverride
	}
	if *nonceHex != "" {
		n, err := hex.DecodeString(*nonceHex)
		if err != nil || len(n) != spa.NonceLen {
			log.Fatalf("nonce 必须是 %d 字节的 hex", spa.NonceLen)
		}
		copy(pkt.Nonce[:], n)
	}

	data, err := pkt.Marshal(key)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("udp", *server)
	if err != nil {
		log.Fatalf("连接 %s: %v", *server, err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		log.Fatalf("发送失败: %v", err)
	}
	fmt.Printf("已发送授权包: user=%s port=%d duration=%ds -> %s (%d 字节)\n",
		*user, *port, *duration, *server, len(data))
	fmt.Println("提示: UDP 无回执, 是否放行请查看服务端管理页或日志")
}
