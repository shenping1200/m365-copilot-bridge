package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type apiKeyRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"hash"`
	Key        string     `json:"key,omitempty"` // 明文 key 仅创建时写入;list 接口会清空,仅 reveal 接口返回。⚠️ 明文落盘,data 卷请妥善保护。
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Revoked    bool       `json:"revoked"`
}
type apiKeyStore struct {
	mu   sync.Mutex
	Path string
	Keys []apiKeyRecord `json:"keys"`
}

func openAPIKeys() *apiKeyStore {
	p := strings.TrimSpace(os.Getenv("M365_API_KEYS"))
	if p == "" {
		h, _ := os.UserHomeDir()
		p = filepath.Join(h, ".config", "m365-native", "api-keys.json")
	}
	s := &apiKeyStore{Path: p}
	b, e := os.ReadFile(p)
	if e == nil {
		_ = json.Unmarshal(b, s)
	}
	return s
}
func (s *apiKeyStore) save() {
	_ = os.MkdirAll(filepath.Dir(s.Path), 0700)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(s.Path, b, 0600)
}
func keyHash(k string) string { h := sha256.Sum256([]byte(k)); return hex.EncodeToString(h[:]) }
func (s *apiKeyStore) create(name string, days int) (apiKeyRecord, string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return apiKeyRecord{}, "", e
	}
	raw := "m365_" + hex.EncodeToString(b)
	r := apiKeyRecord{ID: hex.EncodeToString(b[:8]), Name: name, Prefix: raw[:12], Hash: keyHash(raw), Key: raw, CreatedAt: time.Now()}
	if days > 0 {
		exp := time.Now().AddDate(0, 0, days)
		r.ExpiresAt = &exp
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Keys = append(s.Keys, r)
	s.save()
	return r, raw, nil
}
func (s *apiKeyStore) list() []apiKeyRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apiKeyRecord, len(s.Keys))
	copy(out, s.Keys)
	for i := range out {
		out[i].Hash = ""
		out[i].Key = "" // list 接口绝不返回明文 key;只有 reveal 接口返回。
	}
	return out
}
func (s *apiKeyStore) revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Keys {
		if s.Keys[i].ID == id {
			// 幂等：已撤销的 key 再次撤销仍视为成功，避免前端重复点击时返回 404
			if !s.Keys[i].Revoked {
				s.Keys[i].Revoked = true
				s.save()
			}
			return true
		}
	}
	return false
}
func (s *apiKeyStore) valid(raw string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := keyHash(raw)
	now := time.Now()
	for i := range s.Keys {
		if s.Keys[i].Hash == h && !s.Keys[i].Revoked {
			if s.Keys[i].ExpiresAt != nil && now.After(*s.Keys[i].ExpiresAt) {
				// expired key: not valid, but keep the record visible in the UI
				continue
			}
			s.Keys[i].LastUsedAt = &now
			s.save()
			return true
		}
	}
	return false
}
func (s *apiKeyStore) setExpiry(id string, days int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Keys {
		if s.Keys[i].ID == id {
			if days > 0 {
				exp := time.Now().AddDate(0, 0, days)
				s.Keys[i].ExpiresAt = &exp
			} else {
				s.Keys[i].ExpiresAt = nil
			}
			s.save()
			return true
		}
	}
	return false
}

// reveal 返回明文 key。要求调用者已经走 admin session 中间件。
// 历史 key(创建于本改动之前)字段 Key 为空,会返回 notFound 以提示前端用户需新建。
func (s *apiKeyStore) reveal(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Keys {
		if s.Keys[i].ID == id {
			if s.Keys[i].Key == "" {
				return "", false // 历史 key,无明文记录
			}
			return s.Keys[i].Key, true
		}
	}
	return "", false
}
