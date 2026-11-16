package spa

import (
	"sync"
	"time"
)

// AuthEvent 记录一次授权请求的处理结果(成功或拒绝及原因)。
type AuthEvent struct {
	Time   time.Time `json:"time"`
	IP     string    `json:"ip"`
	User   string    `json:"user"`
	Port   uint16    `json:"port"`
	OK     bool      `json:"ok"`
	Reason string    `json:"reason"`
}

// AuthLog 是固定容量的内存环形日志, 网页上展示最近的记录。
type AuthLog struct {
	mu     sync.Mutex
	events []AuthEvent
	cap    int
}

func NewAuthLog(capacity int) *AuthLog { return &AuthLog{cap: capacity} }

func (l *AuthLog) Add(e AuthEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	if len(l.events) > l.cap {
		l.events = l.events[len(l.events)-l.cap:]
	}
}

// Recent 返回全部记录, 最新的在前。
func (l *AuthLog) Recent() []AuthEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuthEvent, len(l.events))
	for i, e := range l.events {
		out[len(l.events)-1-i] = e
	}
	return out
}
