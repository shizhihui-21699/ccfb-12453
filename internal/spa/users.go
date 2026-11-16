package spa

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// User 是一个授权用户, Key 为 32 字节随机密钥的 hex 编码。
type User struct {
	ID      string `json:"id"`
	KeyHex  string `json:"key"`
	Revoked bool   `json:"revoked"`
	key     []byte
}

// UserStore 从 users.json 加载用户, 吊销会写回文件持久化。
type UserStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]*User
}

func LoadUsers(path string) (*UserStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list struct {
		Users []*User `json:"users"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s := &UserStore{path: path, users: map[string]*User{}}
	for _, u := range list.Users {
		k, err := hex.DecodeString(u.KeyHex)
		if err != nil || len(k) == 0 {
			return nil, fmt.Errorf("user %q: invalid key", u.ID)
		}
		u.key = k
		s.users[u.ID] = u
	}
	return s, nil
}

func (s *UserStore) Get(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

// Key 返回用户的解码后密钥, 用于校验 HMAC。
func (u *User) Key() []byte { return u.key }

func (s *UserStore) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Revoke 吊销用户并写回 users.json。
func (s *UserStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return errors.New("no such user")
	}
	u.Revoked = true
	return s.saveLocked()
}

func (s *UserStore) saveLocked() error {
	list := struct {
		Users []*User `json:"users"`
	}{}
	for _, u := range s.users {
		list.Users = append(list.Users, u)
	}
	sort.Slice(list.Users, func(i, j int) bool { return list.Users[i].ID < list.Users[j].ID })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
