package spa

import (
	"log"
	"net"
	"sync"
	"time"
)

// Server 是 SPA 授权服务端: 收 UDP 包, 校验, 放行。
type Server struct {
	Users    *UserStore
	Firewall *MockFirewall
	Log      *AuthLog
	MaxOpen  time.Duration // 单次放行时长上限
	Window   time.Duration // 时间戳容忍窗口(±)

	mu     sync.Mutex
	nonces map[[NonceLen]byte]time.Time // 已见 nonce -> 过期清理时间
}

func NewServer(users *UserStore, fw *MockFirewall, al *AuthLog, maxOpen, window time.Duration) *Server {
	return &Server{
		Users: users, Firewall: fw, Log: al,
		MaxOpen: maxOpen, Window: window,
		nonces: map[[NonceLen]byte]time.Time{},
	}
}

// ListenAndServe 在 addr(如 ":62201")上监听 UDP 并循环处理包。
func (s *Server) ListenAndServe(addr string) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("spa: listening on udp %s", conn.LocalAddr())

	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		// 同步处理: 校验是纯 CPU 操作且量小, 同步能保证日志顺序确定(测试依赖这点)。
		s.Handle(src, data)
	}
}

// Handle 处理一个数据报, 结果记入 AuthLog。
func (s *Server) Handle(src *net.UDPAddr, data []byte) {
	ip := src.IP.String()
	ev := AuthEvent{Time: time.Now(), IP: ip}
	deny := func(user string, port uint16, reason string) {
		ev.User, ev.Port, ev.OK, ev.Reason = user, port, false, reason
		s.Log.Add(ev)
		log.Printf("auth: DENY  ip=%s user=%q port=%d reason=%s", ip, user, port, reason)
	}

	pkt, signed, mac, err := Unmarshal(data)
	if err != nil {
		deny("", 0, "malformed: "+err.Error())
		return
	}
	u, ok := s.Users.Get(pkt.UserID)
	if !ok {
		deny(pkt.UserID, pkt.Port, "unknown user")
		return
	}
	if u.Revoked {
		deny(pkt.UserID, pkt.Port, "user revoked")
		return
	}
	if !VerifyMAC(u.Key(), signed, mac) {
		deny(pkt.UserID, pkt.Port, "bad signature")
		return
	}
	now := time.Now()
	if d := now.Sub(time.Unix(pkt.Timestamp, 0)); d > s.Window || d < -s.Window {
		deny(pkt.UserID, pkt.Port, "timestamp outside window")
		return
	}
	if !s.claimNonce(pkt.Nonce, now) {
		deny(pkt.UserID, pkt.Port, "replay detected")
		return
	}

	dur := time.Duration(pkt.Duration) * time.Second
	if dur <= 0 || dur > s.MaxOpen {
		dur = s.MaxOpen
	}
	rule := s.Firewall.Open(ip, pkt.Port, pkt.UserID, dur)
	ev.User, ev.Port, ev.OK, ev.Reason = pkt.UserID, pkt.Port, true, "granted"
	s.Log.Add(ev)
	log.Printf("auth: GRANT ip=%s user=%q port=%d rule=#%d ttl=%s", ip, pkt.UserID, pkt.Port, rule.ID, dur)
}

// claimNonce 记录 nonce; 已见过(未过期)则返回 false 表示重放。
func (s *Server) claimNonce(n [NonceLen]byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, k)
		}
	}
	if _, seen := s.nonces[n]; seen {
		return false
	}
	// 保留 2 倍窗口: 即使包在时间窗边缘, 重发到达时 nonce 仍未被清理。
	s.nonces[n] = now.Add(s.Window * 2)
	return true
}
