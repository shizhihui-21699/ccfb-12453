# SPA Gateway — 单包授权服务

把 SSH 等端口藏在防火墙后面: 客户端发一个带 HMAC 签名的 UDP 包,
服务端校验通过后**只对来源 IP** 临时放开指定端口, 到期自动关闭。

## 包格式(单 UDP 数据报, 大端序)

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 2 | magic `SP` |
| 2 | 1 | version (=1) |
| 3 | 1 | userID 长度 (1–32) |
| 4 | N | userID |
| 4+N | 8 | timestamp (Unix 秒) |
| 12+N | 16 | nonce (随机) |
| 28+N | 2 | port (请求放开的端口) |
| 30+N | 4 | duration (请求秒数, 服务端钳制上限) |
| 34+N | 32 | HMAC-SHA256(以上全部, key=用户密钥) |

**防重放**: 时间戳必须在 ±60s 窗口内, 且 nonce 在窗口期内唯一 ——
抓到的包过一会再发, 要么时间戳过期, 要么 nonce 已见, 都会被拒。

## 快速开始

```sh
# 1. 给每个用户生成密钥
go build -o bin/spad ./cmd/spad
go build -o bin/spa-client ./cmd/spa-client
./bin/spa-client -genkey   # 输出 hex 密钥

# 2. 写 users.json (吊销把 revoked 改 true, 或在网页上点吊销)
cat > users.json <<EOF
{"users":[{"id":"alice","key":"<上面生成的hex>","revoked":false}]}
EOF

# 3. 启动服务端 (UDP 授权端口 + 管理网页)
./bin/spad -listen :62201 -http :8080 -users users.json

# 4. 客户端敲门, 然后 30 秒内可以连 SSH
./bin/spa-client -server <服务器IP>:62201 -user alice -key <hex> -port 22 -duration 60
ssh user@<服务器IP>
```

管理页 `http://localhost:8080`: 当前放开的规则、用户列表(可吊销)、最近授权记录, 2 秒自动刷新。

## 服务端参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-listen` | `:62201` | UDP 授权包监听地址 |
| `-http` | `:8080` | 管理网页地址 |
| `-users` | `users.json` | 用户密钥文件 |
| `-max-open` | `300s` | 单次放行时长上限 |
| `-window` | `60s` | 时间戳容忍窗口(±) |

## 测试

```sh
go test ./...        # 单元测试: 包编解码/篡改/重放/吊销/过期
./scripts/test.sh    # 端到端: 起真实服务端跑 6 个场景
```

## 接真实防火墙

`internal/spa/firewall.go` 里的 `MockFirewall` 只改内存并打日志。
生产环境把 `Open`/`expireLocked` 两处换成调用 nftables/iptables/pf 即可, 例如:

```sh
nft add rule inet filter input ip saddr <IP> tcp dport <PORT> accept timeout <N>s
```

## 注意

- UDP 无回执: 客户端不知道是否放行, 以管理页/日志为准(这是 SPA 的常态, fwknop 也一样)。
- 授权端口本身对扫描者表现为"端口不存在"(UDP 无响应), 这正是隐藏效果。
- 密钥即全部凭据, `users.json` 权限设为 600, 不要进 git。
