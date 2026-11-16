package spa

import (
	"log"
	"sort"
	"sync"
	"time"
)

// Rule 是一条临时放行规则: 允许 IP 访问本机 Port, 到 ExpiresAt 自动关闭。
type Rule struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Port      uint16    `json:"port"`
	User      string    `json:"user"`
	OpenedAt  time.Time `json:"opened_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MockFirewall 是本地模拟防火墙: 规则只保存在内存里并打日志,
// 真实部署时把 Open/expireLocked 换成调用 iptables/nftables/pf 即可。
type MockFirewall struct {
	mu     sync.Mutex
	nextID int64
	rules  map[int64]*Rule
	now    func() time.Time // 测试可注入
}

func NewMockFirewall() *MockFirewall {
	fw := &MockFirewall{rules: map[int64]*Rule{}, now: time.Now}
	go fw.janitor()
	return fw
}

// Open 添加一条 d 时长后自动失效的规则。
func (f *MockFirewall) Open(ip string, port uint16, user string, d time.Duration) Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	now := f.now()
	r := &Rule{ID: f.nextID, IP: ip, Port: port, User: user, OpenedAt: now, ExpiresAt: now.Add(d)}
	f.rules[r.ID] = r
	log.Printf("firewall: OPEN  %s:%d user=%q rule=#%d expires=%s",
		ip, port, user, r.ID, r.ExpiresAt.Format("15:04:05"))
	return *r
}

// List 返回当前生效的规则(先惰性清理过期项), 按过期时间排序。
func (f *MockFirewall) List() []Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expireLocked(f.now())
	out := make([]Rule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

func (f *MockFirewall) expireLocked(now time.Time) {
	for id, r := range f.rules {
		if !now.Before(r.ExpiresAt) {
			log.Printf("firewall: CLOSE %s:%d rule=#%d expired", r.IP, r.Port, r.ID)
			delete(f.rules, id)
		}
	}
}

// janitor 每秒扫一次, 关掉到期的规则。
func (f *MockFirewall) janitor() {
	t := time.NewTicker(time.Second)
	for range t.C {
		f.mu.Lock()
		f.expireLocked(f.now())
		f.mu.Unlock()
	}
}
