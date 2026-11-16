package spa

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPacketRoundTrip(t *testing.T) {
	key := testKey(t)
	in := &Packet{UserID: "alice", Timestamp: time.Now().Unix(), Port: 22, Duration: 120}
	if _, err := rand.Read(in.Nonce[:]); err != nil {
		t.Fatal(err)
	}
	data, err := in.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	out, signed, mac, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if out.UserID != in.UserID || out.Timestamp != in.Timestamp ||
		out.Port != in.Port || out.Duration != in.Duration || out.Nonce != in.Nonce {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
	if !VerifyMAC(key, signed, mac) {
		t.Fatal("MAC should verify with correct key")
	}
	if VerifyMAC(testKey(t), signed, mac) {
		t.Fatal("MAC must not verify with wrong key")
	}
}

func TestUnmarshalRejectsTampering(t *testing.T) {
	key := testKey(t)
	p := &Packet{UserID: "bob", Timestamp: time.Now().Unix(), Port: 22, Duration: 60}
	data, err := p.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	// 篡改端口字段
	tampered := bytes.Clone(data)
	tampered[len(tampered)-hmacLen-3] ^= 0xff
	out, signed, mac, err := Unmarshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyMAC(key, signed, mac) {
		t.Fatalf("tampered packet (port now %d) must fail MAC check", out.Port)
	}
	// 截断
	if _, _, _, err := Unmarshal(data[:len(data)-1]); err == nil {
		t.Fatal("truncated packet must be rejected")
	}
	// 错误 magic
	bad := bytes.Clone(data)
	bad[0] = 'X'
	if _, _, _, err := Unmarshal(bad); err == nil {
		t.Fatal("bad magic must be rejected")
	}
}

// newTestServer 建一个内存服务端, 防火墙时钟可手动拨快。
func newTestServer(t *testing.T, key []byte) (*Server, *MockFirewall) {
	t.Helper()
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users.json")
	content := `{"users":[{"id":"alice","key":"` + hex.EncodeToString(key) + `","revoked":false}]}`
	if err := os.WriteFile(usersFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := LoadUsers(usersFile)
	if err != nil {
		t.Fatal(err)
	}
	fw := &MockFirewall{rules: map[int64]*Rule{}, now: time.Now} // 不起 janitor, 手动控制
	return NewServer(users, fw, NewAuthLog(100), 300*time.Second, 60*time.Second), fw
}

func send(t *testing.T, s *Server, key []byte, p *Packet, ip string) {
	t.Helper()
	data, err := p.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(&net.UDPAddr{IP: net.ParseIP(ip), Port: 50000}, data)
}

func TestServerGrantReplayExpire(t *testing.T) {
	key := testKey(t)
	s, fw := newTestServer(t, key)

	p := &Packet{UserID: "alice", Timestamp: time.Now().Unix(), Port: 22, Duration: 5}
	if _, err := rand.Read(p.Nonce[:]); err != nil {
		t.Fatal(err)
	}

	// 1. 正常授权 -> 放行
	send(t, s, key, p, "1.2.3.4")
	if rules := fw.List(); len(rules) != 1 || rules[0].IP != "1.2.3.4" || rules[0].Port != 22 {
		t.Fatalf("expected one rule for 1.2.3.4:22, got %+v", rules)
	}

	// 2. 同一个包重发 -> 拒绝(重放)
	send(t, s, key, p, "1.2.3.4")
	if rules := fw.List(); len(rules) != 1 {
		t.Fatalf("replay must not open a second rule, got %+v", rules)
	}
	last := s.Log.Recent()[0]
	if last.OK || last.Reason != "replay detected" {
		t.Fatalf("expected replay rejection, got %+v", last)
	}

	// 3. 旧时间戳 -> 拒绝
	stale := &Packet{UserID: "alice", Timestamp: time.Now().Add(-10 * time.Minute).Unix(), Port: 22, Duration: 5}
	rand.Read(stale.Nonce[:])
	send(t, s, key, stale, "1.2.3.4")
	if last := s.Log.Recent()[0]; last.OK || last.Reason != "timestamp outside window" {
		t.Fatalf("expected stale timestamp rejection, got %+v", last)
	}

	// 4. 错误密钥 -> 拒绝
	fresh := &Packet{UserID: "alice", Timestamp: time.Now().Unix(), Port: 22, Duration: 5}
	rand.Read(fresh.Nonce[:])
	send(t, s, testKey(t), fresh, "1.2.3.4")
	if last := s.Log.Recent()[0]; last.OK || last.Reason != "bad signature" {
		t.Fatalf("expected bad signature rejection, got %+v", last)
	}

	// 5. 到期自动关闭: 把防火墙时钟拨到 6 秒后
	base := time.Now()
	fw.now = func() time.Time { return base.Add(6 * time.Second) }
	if rules := fw.List(); len(rules) != 0 {
		t.Fatalf("rule should have expired, got %+v", rules)
	}
}

func TestServerRevokedUser(t *testing.T) {
	key := testKey(t)
	s, fw := newTestServer(t, key)
	if err := s.Users.Revoke("alice"); err != nil {
		t.Fatal(err)
	}
	p := &Packet{UserID: "alice", Timestamp: time.Now().Unix(), Port: 22, Duration: 5}
	rand.Read(p.Nonce[:])
	send(t, s, key, p, "1.2.3.4")
	if rules := fw.List(); len(rules) != 0 {
		t.Fatalf("revoked user must not open rules, got %+v", rules)
	}
	if last := s.Log.Recent()[0]; last.OK || last.Reason != "user revoked" {
		t.Fatalf("expected revocation rejection, got %+v", last)
	}
}
