// spad 是单包授权(SPA)服务端: 监听 UDP 授权包, 校验通过后
// 在(模拟)防火墙上对来源 IP 临时放开指定端口, 并提供管理网页。
package main

import (
	"flag"
	"log"
	"time"

	"spa/internal/spa"
)

func main() {
	listen := flag.String("listen", ":62201", "UDP 监听地址(授权包)")
	httpAddr := flag.String("http", ":8080", "管理网页监听地址")
	usersPath := flag.String("users", "users.json", "用户密钥文件")
	maxOpen := flag.Duration("max-open", 300*time.Second, "单次放行时长上限")
	window := flag.Duration("window", 60*time.Second, "时间戳容忍窗口(±)")
	flag.Parse()

	users, err := spa.LoadUsers(*usersPath)
	if err != nil {
		log.Fatalf("load users: %v", err)
	}
	fw := spa.NewMockFirewall()
	authLog := spa.NewAuthLog(200)
	srv := spa.NewServer(users, fw, authLog, *maxOpen, *window)

	go func() {
		log.Printf("web: admin page on http://localhost%s", *httpAddr)
		if err := spa.StartWeb(*httpAddr, srv); err != nil {
			log.Fatalf("web: %v", err)
		}
	}()

	log.Fatal(srv.ListenAndServe(*listen))
}
