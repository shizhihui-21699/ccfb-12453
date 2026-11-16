#!/usr/bin/env bash
# 端到端测试: 构建 -> 起服务端 -> 正常授权/重放/错密钥/吊销/自动过期
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'kill $SPAD_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== 构建 =="
go build -o "$TMP/spad" ./cmd/spad
go build -o "$TMP/spa-client" ./cmd/spa-client

UDP_PORT=16201
HTTP_PORT=18080
KEY_ALICE=$("$TMP/spa-client" -genkey)
KEY_BOB=$("$TMP/spa-client" -genkey)
cat > "$TMP/users.json" <<EOF
{"users":[
  {"id":"alice","key":"$KEY_ALICE","revoked":false},
  {"id":"bob","key":"$KEY_BOB","revoked":false}
]}
EOF

echo "== 启动服务端 (udp:$UDP_PORT http:$HTTP_PORT) =="
"$TMP/spad" -listen ":$UDP_PORT" -http ":$HTTP_PORT" -users "$TMP/users.json" \
  -max-open 300s -window 60s > "$TMP/spad.log" 2>&1 &
SPAD_PID=$!
for i in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$HTTP_PORT/api/rules" >/dev/null 2>&1 && break
  sleep 0.1
done

fail() { echo "FAIL: $1"; echo "--- spad.log ---"; cat "$TMP/spad.log"; exit 1; }

echo "== 1. 正常授权 =="
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user alice -key "$KEY_ALICE" -port 22 -duration 30
sleep 0.3
curl -sf "http://127.0.0.1:$HTTP_PORT/api/rules" | grep -q '"port":22' || fail "规则未放开"
echo "OK: 规则已放开"

echo "== 2. 重放同一个包(固定 ts+nonce) =="
TS=$(date +%s)
NONCE="00112233445566778899001122334455"
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user bob -key "$KEY_BOB" -port 2222 -duration 30 -ts "$TS" -nonce "$NONCE" >/dev/null
sleep 0.2
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user bob -key "$KEY_BOB" -port 2222 -duration 30 -ts "$TS" -nonce "$NONCE" >/dev/null
sleep 0.3
curl -sf "http://127.0.0.1:$HTTP_PORT/api/log" | grep -q "replay detected" || fail "重放未被拒绝"
echo "OK: 重放被拒绝"

echo "== 3. 过期时间戳 =="
OLD_TS=$(( $(date +%s) - 600 ))
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user alice -key "$KEY_ALICE" -port 22 -ts "$OLD_TS" >/dev/null
sleep 0.3
curl -sf "http://127.0.0.1:$HTTP_PORT/api/log" | grep -q "timestamp outside window" || fail "过期包未被拒绝"
echo "OK: 过期时间戳被拒绝"

echo "== 4. 错误密钥 =="
WRONG_KEY=$("$TMP/spa-client" -genkey)
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user alice -key "$WRONG_KEY" -port 22 >/dev/null
sleep 0.3
curl -sf "http://127.0.0.1:$HTTP_PORT/api/log" | grep -q "bad signature" || fail "错误密钥未被拒绝"
echo "OK: 错误密钥被拒绝"

echo "== 5. 吊销用户 =="
curl -sf -X POST "http://127.0.0.1:$HTTP_PORT/api/users/revoke?id=bob" >/dev/null
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user bob -key "$KEY_BOB" -port 2222 >/dev/null
sleep 0.3
curl -sf "http://127.0.0.1:$HTTP_PORT/api/log" | grep -q "user revoked" || fail "吊销用户未被拒绝"
echo "OK: 吊销生效"

echo "== 6. 到期自动关闭 =="
"$TMP/spa-client" -server "127.0.0.1:$UDP_PORT" -user alice -key "$KEY_ALICE" -port 9999 -duration 2 >/dev/null
sleep 0.3
curl -sf "http://127.0.0.1:$HTTP_PORT/api/rules" | grep -q '"port":9999' || fail "9999 规则未放开"
sleep 3
if curl -sf "http://127.0.0.1:$HTTP_PORT/api/rules" | grep -q '"port":9999'; then
  fail "9999 规则到期后仍存在"
fi
echo "OK: 规则到期自动关闭"

echo
echo "全部通过 ✅  (管理页: http://127.0.0.1:$HTTP_PORT)"
