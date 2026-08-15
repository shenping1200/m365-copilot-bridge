package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"m365-native/internal/auth"
	"m365-native/internal/chathub"
	"m365-native/internal/proxy"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type pendingPKCE struct {
	Verifier string
	Created  time.Time
}

type Server struct {
	mu                 sync.Mutex
	accountIdx         int
	tokens             *auth.Store
	pkce               map[string]pendingPKCE
	chat               *chathub.Client
	sessions           *sessionStore
	adminPassword      string
	adminSessions      map[string]time.Time
	mustChangePassword bool
	loginAttempts      map[string]loginAttempt
	apiKeys            *apiKeyStore
	debug              *debugStore
	settings           *settingsStore
	accountStats       map[string]int64
		accountTokenIn  map[string]int64
		accountTokenOut map[string]int64
	statsPath          string
	statsDirty         bool
	accountPool        *accountHealth
	accountPoolOnce    sync.Once
}

func New() (*Server, error) {
	store, err := auth.OpenStore("")
	if err != nil {
		return nil, err
	}
	password, mustChange := loadAdminPassword()
	s := &Server{
		tokens:             store,
		pkce:               map[string]pendingPKCE{},
		chat:               chathub.NewClient(),
		sessions:           openSessionStore(),
		adminPassword:      password,
		adminSessions:      map[string]time.Time{},
		mustChangePassword: mustChange,
		loginAttempts:      map[string]loginAttempt{},
		apiKeys:            openAPIKeys(),
		debug:              openDebugStore(),
		settings:           openSettingsStore(),
		accountStats:       make(map[string]int64),
		accountTokenIn:     make(map[string]int64),
		accountTokenOut:    make(map[string]int64),
		statsPath:          filepath.Join(filepath.Dir(auth.CachePath()), "stats.json"),
	}
	s.loadStats()
	go s.statsSaver()
	return s, nil
}

func (s *Server) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/api/admin/login", s.adminLogin)
	m.HandleFunc("/api/admin/logout", s.adminLogout)
	m.HandleFunc("/api/admin/session", s.adminSession)
	m.HandleFunc("/api/admin/change-password", s.adminChangePassword)
	m.HandleFunc("/api/admin/keys", s.adminKeys)
	m.HandleFunc("/api/admin/settings", s.adminSettings)
	m.HandleFunc("/api/admin/debug/logs", s.debugList)
	m.HandleFunc("/api/admin/debug/detail", s.debugDetail)
	m.HandleFunc("/api/health", s.health)
	m.HandleFunc("/api/accounts", s.accounts)
	m.HandleFunc("/api/accounts/refresh", s.refreshAccount)
	m.HandleFunc("/api/accounts/delete", s.deleteAccount)
	m.HandleFunc("/api/accounts/proxy", s.updateAccountProxy)
	m.HandleFunc("/api/admin/test-proxy", s.testProxy)
	m.HandleFunc("/api/admin/test-all-proxies", s.testAllProxies)
	m.HandleFunc("/api/admin/reset-stats", s.resetStatsHandler)
	m.HandleFunc("/api/auth/start", s.startPKCE)
	m.HandleFunc("/api/auth/callback", s.callbackPKCE)
	m.HandleFunc("/api/chat", s.chatOnce)
	m.HandleFunc("/api/chat/stream", s.chatStream)
	m.HandleFunc("/api/conversations", s.conversations)
	m.HandleFunc("/api/conversations/delete", s.deleteConversation)
	m.HandleFunc("/v1/models", s.openaiModels)
	m.HandleFunc("/v1/chat/completions", s.openaiChat)
	m.HandleFunc("/v1/responses", s.responses)
	m.HandleFunc("/v1/messages", s.anthropicMessages)
	m.HandleFunc("/v1/images/generations", s.imageGenerations)
	m.HandleFunc("/", s.rootPage)
	return requestID(securityHeaders(s.adminMiddleware(s.debugMiddleware(m))))
}

func (s *Server) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/login" || r.URL.Path == "/api/admin/session" || r.URL.Path == "/api/admin/change-password" || r.URL.Path == "/api/admin/logout" || r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			if !s.validAPIKey(r) {
				http.Error(w, `{"error":{"message":"valid API key required","type":"auth_error"}}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if s.adminPassword == "" {
			http.Error(w, `{"error":{"message":"administrator password is not configured","type":"configuration_error"}}`, http.StatusServiceUnavailable)
			return
		}
		if !s.validAdminSession(r) {
			writeOpenAIError(w, http.StatusUnauthorized, "auth_error", "administrator login required")
			return
		}
		s.mu.Lock()
		mustChange := s.mustChangePassword
		s.mu.Unlock()
		if mustChange && r.URL.Path != "/api/admin/change-password" && r.URL.Path != "/api/admin/logout" {
			writeOpenAIError(w, http.StatusForbidden, "password_change_required", "administrator password must be changed before using the console")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) validAdminSession(r *http.Request) bool {
	c, err := r.Cookie("m365_admin_session")
	if err != nil || c.Value == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.adminSessions[c.Value]
	if !ok || time.Now().After(expires) {
		delete(s.adminSessions, c.Value)
		return false
	}
	return true
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed")
		return
	}
	ip, now := clientIP(r), time.Now()
	if ok, wait := s.loginAllowed(ip, now); !ok {
		seconds := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprint(seconds))
		writeOpenAIError(w, http.StatusTooManyRequests, "rate_limit_error", "too many failed login attempts; try again later")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	s.mu.Lock()
	password := s.adminPassword
	mustChange := s.mustChangePassword
	s.mu.Unlock()
	if decodeErr != nil || body.Password == "" || subtle.ConstantTimeCompare([]byte(body.Password), []byte(password)) != 1 {
		s.recordLoginFailure(ip, now)
		writeOpenAIError(w, http.StatusUnauthorized, "auth_error", "invalid administrator password")
		return
	}
	s.clearLoginFailures(ip)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeOpenAIError(w, 500, "internal_error", "session failure")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.adminSessions[token] = time.Now().Add(24 * time.Hour)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "m365_admin_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
	jsonOut(w, map[string]any{"status": "authenticated", "must_change_password": mustChange})
}
func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("m365_admin_session"); e == nil {
		s.mu.Lock()
		delete(s.adminSessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "m365_admin_session", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	jsonOut(w, map[string]string{"status": "logged_out"})
}
func (s *Server) adminSession(w http.ResponseWriter, r *http.Request) {
	authenticated := s.validAdminSession(r)
	s.mu.Lock()
	mustChange := s.mustChangePassword
	s.mu.Unlock()
	jsonOut(w, map[string]bool{"authenticated": authenticated, "must_change_password": authenticated && mustChange})
}

func (s *Server) adminKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, map[string]any{"keys": s.apiKeys.list()})
	case http.MethodPost:
		var b struct {
			Name string `json:"name"`
			Days int    `json:"days"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if strings.TrimSpace(b.Name) == "" {
			b.Name = "API key"
		}
		rec, raw, e := s.apiKeys.create(b.Name, b.Days)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		jsonOut(w, map[string]any{"key": raw, "record": rec})
	case http.MethodPatch:
		var b struct {
			ID   string `json:"id"`
			Days int    `json:"days"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil || b.ID == "" {
			http.Error(w, "bad json", 400)
			return
		}
		if !s.apiKeys.setExpiry(b.ID, b.Days) {
			http.Error(w, "key not found", 404)
			return
		}
		jsonOut(w, map[string]string{"status": "updated"})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if !s.apiKeys.revoke(id) {
			http.Error(w, "key not found", 404)
			return
		}
		jsonOut(w, map[string]string{"status": "revoked"})
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) validAPIKey(r *http.Request) bool {
	raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if raw == "" {
		v := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(v), "bearer ") {
			raw = strings.TrimSpace(v[7:])
		}
	}
	return raw != "" && s.apiKeys.valid(raw)
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	list := s.tokens.List()
	jsonOut(w, map[string]any{
		"status":       "ok",
		"auth":         []string{"pkce"},
		"chat":         "chathub",
		"clientId":     auth.ClientID(),
		"scope":        auth.Scope(),
		"tokenCache":   s.tokens.Path(),
		"accountCount": len(list),
	})
}

func (s *Server) accounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	list := s.tokens.List()
	type view struct {
		ID           string            `json:"id"`
		Email        string            `json:"email"`
		DisplayName  string            `json:"displayName,omitempty"`
		Status       string            `json:"status"`
		OID          string            `json:"oid,omitempty"`
		TID          string            `json:"tid,omitempty"`
		ExpiresAt    time.Time         `json:"expiresAt,omitempty"`
		UpdatedAt    time.Time         `json:"updatedAt,omitempty"`
		RequestCount int64             `json:"requestCount"`
		TokenIn  int64 `json:"tokenIn"`
		TokenOut int64 `json:"tokenOut"`
		Proxy        string            `json:"proxy,omitempty"`
		Health       accountHealthView `json:"health,omitempty"`
	}
	out := make([]view, 0, len(list))
	var total int64
	var totalIn, totalOut int64
	healthMap := make(map[string]accountHealthView)
	for _, hv := range s.healthPool().Snapshot() {
		healthMap[hv.AccountID] = hv
	}
	s.mu.Lock()
	for _, a := range list {
		cnt := s.accountStats[a.ID]
		total += cnt
		tin := s.accountTokenIn[a.ID]
		tout := s.accountTokenOut[a.ID]
		totalIn += tin
		totalOut += tout
		out = append(out, view{
			ID: a.ID, Email: a.Email, DisplayName: a.DisplayName,
			Status: a.Status, OID: a.OID, TID: a.TID,
			ExpiresAt: a.ExpiresAt, UpdatedAt: a.UpdatedAt,
			RequestCount: cnt,
			TokenIn:  tin,
			TokenOut: tout,
			Proxy:        a.Proxy,
			Health:       healthMap[a.ID],
		})
	}
	s.mu.Unlock()
	jsonOut(w, map[string]any{"accounts": out, "totalRequestCount": total, "totalTokenIn": totalIn, "totalTokenOut": totalOut})
}

// accountRequestCount returns the per-account request counter under the server
// lock. Reading accountStats without the lock races with the write in
// resolveAccount and triggers Go's fatal "concurrent map read and map write".
func (s *Server) accountRequestCount(id string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accountStats[id]
}

// estimateTokens approximates the token count of a string with a simple
// heuristic: ~4 ASCII chars per token and ~1 token per non-ASCII (e.g. CJK)
// character. M365 Copilot does not expose real token usage, so this value is
// an estimate only and must never be treated as billing-accurate.
func estimateTokens(s string) int {
	ascii, other := 0, 0
	for _, r := range s {
		if r < 0x80 {
			ascii++
		} else {
			other++
		}
	}
	return (ascii + 3) / 4 + other
}

// recordTokens estimates and accumulates input/output token usage for an
// account. It reuses the server mutex that guards the other per-account
// counters so concurrent requests cannot race on the maps.
func (s *Server) recordTokens(id, inputText, outputText string) {
	if id == "" {
		return
	}
	in := int(countTokens("m365-copilot", inputText))
	out := int(countTokens("m365-copilot", outputText))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountTokenIn[id] += int64(in)
	s.accountTokenOut[id] += int64(out)
	s.statsDirty = true
}

// addTokens accumulates a pre-estimated input/output token pair for an account.
func (s *Server) addTokens(id string, in, out int64) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountTokenIn[id] += in
	s.accountTokenOut[id] += out
	s.statsDirty = true
}

// statsFile is the on-disk representation of usage counters so they survive a
// process/container restart.
type statsFile struct {
	Version  int              `json:"version"`
	Stats    map[string]int64 `json:"stats"`
	TokenIn  map[string]int64 `json:"tokenIn"`
	TokenOut map[string]int64 `json:"tokenOut"`
}

// loadStats restores the per-account counters from disk into memory.
func (s *Server) loadStats() {
	if s.statsPath == "" {
		return
	}
	b, err := os.ReadFile(s.statsPath)
	if err != nil {
		return
	}
	var f statsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Stats != nil {
		for k, v := range f.Stats {
			s.accountStats[k] = v
		}
	}
	if f.TokenIn != nil {
		for k, v := range f.TokenIn {
			s.accountTokenIn[k] = v
		}
	}
	if f.TokenOut != nil {
		for k, v := range f.TokenOut {
			s.accountTokenOut[k] = v
		}
	}
}

// saveStats writes the current counters to disk atomically.
func (s *Server) saveStats() {
	if s.statsPath == "" {
		return
	}
	s.mu.Lock()
	f := statsFile{
		Version:  1,
		Stats:    s.accountStats,
		TokenIn:  s.accountTokenIn,
		TokenOut: s.accountTokenOut,
	}
	s.statsDirty = false
	s.mu.Unlock()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(s.statsPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp := s.statsPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.statsPath)
}

// statsSaver periodically flushes counters to disk so a restart does not lose
// more than a few seconds of usage data.
func (s *Server) statsSaver() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		dirty := s.statsDirty
		s.mu.Unlock()
		if dirty {
			s.saveStats()
		}
	}
}

// resetStats zeroes all counters (totals and per-account) and flushes to disk.
func (s *Server) resetStats() {
	s.mu.Lock()
	s.accountStats = make(map[string]int64)
	s.accountTokenIn = make(map[string]int64)
	s.accountTokenOut = make(map[string]int64)
	s.statsDirty = true
	s.mu.Unlock()
	s.saveStats()
}

// resetStatsHandler handles POST /api/admin/reset-stats.
func (s *Server) resetStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validAdminSession(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "auth_error", "administrator session required")
		return
	}
	s.resetStats()
	jsonOut(w, map[string]any{"status": "reset", "totalRequestCount": 0, "totalTokenIn": 0, "totalTokenOut": 0})
}

func (s *Server) refreshAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.ID) == "" {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	acc, err := s.tokens.EnsureValid(strings.TrimSpace(body.ID))
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "token_refresh_error", err.Error())
		return
	}
	jsonOut(w, map[string]any{"status": "refreshed", "account": map[string]any{
		"id": acc.ID, "email": acc.Email, "displayName": acc.DisplayName,
		"status": acc.Status, "expiresAt": acc.ExpiresAt, "updatedAt": acc.UpdatedAt,
	}})
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := s.tokens.Delete(body.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	delete(s.accountStats, body.ID)
	delete(s.accountTokenIn, body.ID)
	delete(s.accountTokenOut, body.ID)
	s.statsDirty = true
	s.mu.Unlock()
	removed := s.sessions.deleteByAccount(body.ID)
	jsonOut(w, map[string]any{"status": "deleted", "sessionsRemoved": removed})
}

func (s *Server) updateAccountProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID    string `json:"id"`
		Proxy string `json:"proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	body.Proxy = strings.TrimSpace(body.Proxy)
	cfg, err := proxy.Parse(body.Proxy)
	if err != nil {
		http.Error(w, "代理格式错误: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.tokens.SetProxy(body.ID, cfg.Raw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOut(w, map[string]any{"status": "ok", "proxy": cfg.Raw})
}

func (s *Server) testProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Proxy string `json:"proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	body.Proxy = strings.TrimSpace(body.Proxy)
	cfg, err := proxy.Parse(body.Proxy)
	if err != nil {
		jsonOut(w, map[string]any{"ok": false, "error": "代理格式错误: " + err.Error()})
		return
	}
	if cfg.Type == proxy.KindDirect {
		jsonOut(w, map[string]any{"ok": true, "direct": true, "note": "直连(未配置代理)"})
		return
	}
	client, err := cfg.HTTPClient()
	if err != nil {
		jsonOut(w, map[string]any{"ok": false, "error": "代理不可用: " + err.Error()})
		return
	}
	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, "https://api.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	if err != nil {
		jsonOut(w, map[string]any{"ok": false, "error": "连接失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var o struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(b, &o)
	jsonOut(w, map[string]any{
		"ok":        resp.StatusCode == http.StatusOK,
		"ip":        o.IP,
		"status":    resp.StatusCode,
		"latencyMs": time.Since(start).Milliseconds(),
	})
}

// testAllProxies iterates every account that has a proxy configured and
// probes it concurrently through the same /api/admin/test-proxy code path.
// The result list preserves account order so the frontend can update each
// row's status inline. Accounts without a proxy are skipped (the UI can
// query /api/accounts to know the full account count).
func (s *Server) testAllProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	list := s.tokens.List()
	type result struct {
		AccountID   string `json:"accountId"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName,omitempty"`
		Proxy       string `json:"proxy"`
		OK          bool   `json:"ok"`
		IP          string `json:"ip,omitempty"`
		Status      int    `json:"status,omitempty"`
		LatencyMs   int64  `json:"latencyMs"`
		Error       string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(list))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range list {
		if strings.TrimSpace(a.Proxy) == "" {
			continue
		}
		wg.Add(1)
		go func(acc auth.AccountToken) {
			defer wg.Done()
			res := result{
				AccountID:   acc.ID,
				Email:       acc.Email,
				DisplayName: acc.DisplayName,
				Proxy:       strings.TrimSpace(acc.Proxy),
			}
			cfg, err := proxy.Parse(res.Proxy)
			if err != nil {
				res.Error = "代理格式错误: " + err.Error()
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				return
			}
			client, err := cfg.HTTPClient()
			if err != nil {
				res.Error = "代理不可用: " + err.Error()
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				return
			}
			start := time.Now()
			req, _ := http.NewRequest(http.MethodGet, "https://api.ipify.org?format=json", nil)
			resp, err := client.Do(req)
			res.LatencyMs = time.Since(start).Milliseconds()
			if err != nil {
				res.Error = "连接失败: " + err.Error()
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			var o struct {
				IP string `json:"ip"`
			}
			_ = json.Unmarshal(b, &o)
			res.OK = resp.StatusCode == http.StatusOK
			res.IP = o.IP
			res.Status = resp.StatusCode
			if !res.OK {
				res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	okCount := 0
	for _, r := range results {
		if r.OK {
			okCount++
		}
	}
	jsonOut(w, map[string]any{
		"results": results,
		"total":   len(results),
		"ok":      okCount,
		"failed":  len(results) - okCount,
	})
}

func (s *Server) startPKCE(w http.ResponseWriter, _ *http.Request) {
	v, err := auth.Verifier()
	if err != nil {
		http.Error(w, "pkce failure", http.StatusInternalServerError)
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "state failure", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(b)
	s.mu.Lock()
	s.pkce[state] = pendingPKCE{Verifier: v, Created: time.Now()}
	s.mu.Unlock()
	jsonOut(w, map[string]string{
		"status": "pkce_ready",
		"state":  state,
		"url": auth.AuthorizationURL(
			auth.AuthorizeEndpoint(),
			auth.ClientID(),
			auth.RedirectURI(),
			state,
			auth.Challenge(v),
			auth.Scope(),
		),
		"redirectUri": auth.RedirectURI(),
		"note":        "If redirect is nativeclient, paste the final URL/code into /api/auth/callback after login.",
	})
}

func (s *Server) callbackPKCE(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	// also accept pasted full callback URL
	if code == "" {
		if u := r.URL.Query().Get("url"); u != "" {
			if parsed, err := http.NewRequest(http.MethodGet, u, nil); err == nil {
				code = parsed.URL.Query().Get("code")
				if state == "" {
					state = parsed.URL.Query().Get("state")
				}
			}
		}
	}
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p, ok := s.pkce[state]
	if ok {
		delete(s.pkce, state)
	}
	s.mu.Unlock()
	if !ok || time.Since(p.Created) > 10*time.Minute {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	tok, err := auth.ExchangeCode(code, p.Verifier, auth.RedirectURI())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acc, err := s.tokens.Upsert(tok)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOut(w, map[string]any{
		"status":  "authenticated",
		"account": map[string]any{"id": acc.ID, "email": acc.Email, "displayName": acc.DisplayName, "status": acc.Status, "oid": acc.OID, "tid": acc.TID},
	})
}

func (s *Server) resolveAccount(accountID string) (auth.AccountToken, error) {
	if accountID != "" {
		tok, err := s.tokens.EnsureValid(accountID)
		if err == nil {
			s.mu.Lock()
			s.accountStats[accountID]++
			s.statsDirty = true
			s.mu.Unlock()
		}
		return tok, err
	}
	list := s.tokens.List()
	if len(list) == 0 {
		return auth.AccountToken{}, fmt.Errorf("no accounts; login first")
	}
	s.mu.Lock()
	start := s.accountIdx % len(list)
	s.accountIdx++
	s.mu.Unlock()
	pool := s.healthPool()
	var lastErr error
	for i := 0; i < len(list); i++ {
		acc := list[(start+i)%len(list)]
		if !pool.Available(acc.ID) {
			continue
		}
		tok, err := s.tokens.EnsureValid(acc.ID)
			if err == nil {
			s.mu.Lock()
			s.accountStats[acc.ID]++
			s.statsDirty = true
			s.mu.Unlock()
			return tok, nil
		}
		lastErr = err
	}
	return auth.AccountToken{}, lastErr
}

type chatBody struct {
	AccountID      string               `json:"accountId"`
	Message        string               `json:"message"`
	Prompt         string               `json:"prompt"`
	Tone           string               `json:"tone"`
	ConversationID string               `json:"conversationId"`
	SessionID      string               `json:"sessionId"`
	SessionKey     string               `json:"sessionKey"`
	Attachments    []chathub.Attachment `json:"attachments,omitempty"`
	Tools          []chathub.Tool       `json:"tools,omitempty"`
	// Legacy OpenAI-compatible clients still send functions/function_call.
	Functions       []json.RawMessage `json:"functions,omitempty"`
	ToolChoice      any               `json:"tool_choice,omitempty"`
	FunctionCall    any               `json:"function_call,omitempty"`
	Reasoning       *reasoningConfig  `json:"reasoning,omitempty"`
	ReasoningEffort string            `json:"reasoning_effort,omitempty"`
}

func modelTone(model string) string {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "gpt-5.2":
		return "Gpt_5_2_Chat"
	case "gpt-5.2-reasoning":
		return "Gpt_5_2_Reasoning"
	case "gpt-5.3":
		return "Gpt_5_3_Chat"
	case "gpt-5.4":
		return "Gpt_5_4_Chat"
	case "gpt-5.4-reasoning":
		return "Gpt_5_4_Reasoning"
	case "gpt-5.5":
		return "Gpt_5_5_Chat"
	case "gpt-5.5-reasoning":
		return "Gpt_5_5_Reasoning"
	case "gpt-5.6-reasoning":
		return "Gpt_5_6_Reasoning"
	case "claude", "claude-sonnet":
		return "Claude_Sonnet"
	case "claude-sonnet-reasoning":
		return "Claude_Sonnet_Reasoning"
	case "gpt-5.4-quick":
		return "Gpt_5_4_Chat"
	case "gpt-5.3-think-deeper":
		return "Gpt_5_3_Chat"
	case "quick":
		return "Gpt_Quick"
	case "think-deeper":
		return "Gpt_Reasoning"
	default:
		return "magic"
	}
}

func (s *Server) chatOnce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body chatBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	text := strings.TrimSpace(firstNonEmpty(body.Message, body.Prompt))
	if text == "" {
		http.Error(w, "message required", http.StatusBadRequest)
		return
	}
	if body.SessionKey != "" {
		if v, ok := s.sessions.get(body.SessionKey); ok {
			body.AccountID = firstNonEmpty(body.AccountID, v.AccountID)
			body.ConversationID = firstNonEmpty(body.ConversationID, v.ConversationID)
			body.SessionID = firstNonEmpty(body.SessionID, v.SessionID)
		}
	}
	acc, err := s.resolveAccount(body.AccountID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if acc.OID == "" || acc.TID == "" {
		// try extract from access token claims on the fly
		if claimsOID, claimsTID := extractOIDTID(acc.AccessToken); claimsOID != "" {
			acc.OID = claimsOID
			acc.TID = claimsTID
		}
	}
	if acc.OID == "" || acc.TID == "" {
		http.Error(w, "account missing oid/tid — re-login with PKCE browser client", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.settings.get().ChatTimeoutSeconds)*time.Second)
	defer cancel()
	req := chathub.Request{
		Text:           text,
		Tone:           body.Tone,
		ConversationID: body.ConversationID,
		SessionID:      body.SessionID,
		Attachments:    body.Attachments,
	}
	account := chathub.Account{AccessToken: acc.AccessToken, OID: acc.OID, TID: acc.TID, Proxy: acc.Proxy}
	res, err := s.chat.Chat(ctx, account, req)
	if err != nil {
		if body.AccountID == "" && (IsRateLimited(err) || IsAuthFailure(err)) {
			if next, nerr := s.nextHealthyAccount(acc.ID); nerr == nil {
				s.markAccountResult(acc.ID, err)
				acc = next
				account = chathub.Account{AccessToken: acc.AccessToken, OID: acc.OID, TID: acc.TID, Proxy: acc.Proxy}
				res, err = s.chat.Chat(ctx, account, req)
			}
		}
		if err != nil {
			s.markAccountResult(acc.ID, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	s.markAccountResult(acc.ID, nil)
	s.recordTokens(acc.ID, text, res.FullText)
	if res.Throttling != nil {
		s.healthPool().MarkRateLimited(acc.ID, time.Time{})
	}
	if body.SessionKey != "" {
		s.sessions.upsert(conversation{ID: body.SessionKey, AccountID: acc.ID, ConversationID: res.ConversationID, SessionID: res.SessionID, Title: text})
	}
	jsonOut(w, map[string]any{
		"status":         "ok",
		"text":           res.Text,
		"conversationId": res.ConversationID,
		"sessionId":      res.SessionID,
		"requestId":      res.RequestID,
		"throttling":     res.Throttling,
		"result":         res.RawResult,
		"events":         res.Events,
		"images":         res.Images,
		"account":        map[string]any{"id": acc.ID, "email": acc.Email},
	})
}

func (s *Server) openaiModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := modelCatalog()
	created := time.Now().Unix()
	for _, model := range data {
		model["created"] = created
	}
	jsonOut(w, map[string]any{"object": "list", "data": data})
}

type oaiMsg struct {
	Role       string           `json:"role"`
	Content    any              `json:"content"`
	Name       string           `json:"name,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	ToolCalls  []map[string]any `json:"tool_calls,omitempty"`
}

type oaiReq struct {
	Model    string   `json:"model"`
	Messages []oaiMsg `json:"messages"`
	Stream   bool     `json:"stream"`
	// optional account routing
	User           string               `json:"user"`
	AccountID      string               `json:"accountId"`
	ConversationID string               `json:"conversation_id"`
	SessionID      string               `json:"session_id"`
	SessionKey     string               `json:"session_key"`
	Attachments    []chathub.Attachment `json:"attachments,omitempty"`
	Tools          []chathub.Tool       `json:"tools,omitempty"`
	// Legacy OpenAI-compatible clients still send functions/function_call.
	Functions       []json.RawMessage `json:"functions,omitempty"`
	ToolChoice      any               `json:"tool_choice,omitempty"`
	FunctionCall    any               `json:"function_call,omitempty"`
	Reasoning       *reasoningConfig  `json:"reasoning,omitempty"`
	ReasoningEffort string            `json:"reasoning_effort,omitempty"`
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func contentToString(c any) string {
	switch v := c.(type) {
	case string:
		return v
	case []any:
		var b strings.Builder
		for _, part := range v {
			if m, ok := part.(map[string]any); ok {
				if t, _ := m["type"].(string); t == "text" || t == "input_text" || t == "output_text" {
					if s, _ := m["text"].(string); s != "" {
						b.WriteString(s)
					}
				}
			}
		}
		return b.String()
	default:
		return fmt.Sprint(v)
	}
}

func normalizeLegacyTools(body *oaiReq) {
	if len(body.Tools) == 0 && len(body.Functions) > 0 {
		body.Tools = make([]chathub.Tool, 0, len(body.Functions))
		for _, f := range body.Functions {
			body.Tools = append(body.Tools, chathub.Tool{Type: "function", Function: f})
		}
	}
	if body.ToolChoice == nil && body.FunctionCall != nil {
		body.ToolChoice = body.FunctionCall
	}
}

// sseRaw writes one SSE frame and flushes; a write error (client gone,
// deadline exceeded) or a canceled request context aborts the stream
// instead of blocking a goroutine against a dead/slow socket.
func sseRaw(ctx context.Context, w http.ResponseWriter, f http.Flusher, payload string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprint(w, payload); err != nil {
		return err
	}
	if f != nil {
		f.Flush()
	}
	return nil
}

func (s *Server) openaiChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var body oaiReq
	if err := json.Unmarshal(raw, &body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	effort := body.ReasoningEffort
	if body.Reasoning != nil && strings.TrimSpace(body.Reasoning.Effort) != "" {
		effort = body.Reasoning.Effort
	}
	tone, toneErr := reasoningTone(body.Model, effort)
	if toneErr != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", toneErr.Error())
		return
	}
	normalizeLegacyTools(&body)
	if err := validateToolConversation(body.Messages); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "tool_protocol_error", err.Error())
		return
	}
	// Rebuild a protocol-neutral evidence ledger from actual tool calls/results.
	// Round limits apply only to the current user turn; full history still informs evidence.
	ledger := buildAgentLedger(body.Messages)
	activeLedger := buildAgentLedger(activeMessages(body.Messages))
	if err := activeLedger.CanContinue(maxToolRounds()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"type": "tool_round_limit", "message": err.Error(), "completed_calls": len(activeLedger.Completed)}})
		return
	}
	// Preserve role boundaries when adapting OpenAI messages to ChatHub's
	// single message.text field. This keeps system/developer instructions,
	// history, and the current user turn distinguishable.
	var prompt string
	prompt, body.Attachments = flattenPromptMessages(body.Messages, body.Attachments)
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		http.Error(w, "messages required", http.StatusBadRequest)
		return
	}

	if body.SessionKey != "" {
		if v, ok := s.sessions.get(body.SessionKey); ok {
			body.AccountID = firstNonEmpty(body.AccountID, v.AccountID)
			body.ConversationID = firstNonEmpty(body.ConversationID, v.ConversationID)
			body.SessionID = firstNonEmpty(body.SessionID, v.SessionID)
		}
	}
	accountID := firstNonEmpty(body.AccountID, body.User)
	acc, err := s.resolveAccount(accountID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if acc.OID == "" || acc.TID == "" {
		if o, t := extractOIDTID(acc.AccessToken); o != "" {
			acc.OID, acc.TID = o, t
		}
	}
	if acc.OID == "" || acc.TID == "" {
		http.Error(w, "account missing oid/tid", http.StatusBadRequest)
		return
	}

	// Normalize tools once. Selection is always made by the upstream model;
	// the gateway only validates its structured decision and converts protocols.
	toolMaps := make([]map[string]any, 0, len(body.Tools))
	for _, tool := range body.Tools {
		var f map[string]any
		_ = json.Unmarshal(tool.Function, &f)
		toolMaps = append(toolMaps, map[string]any{"type": tool.Type, "function": f})
	}
	if body.ToolChoice == nil && len(toolMaps) > 0 {
		body.ToolChoice = "auto"
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.settings.get().ChatTimeoutSeconds)*time.Second)
	defer cancel()
	account := chathub.Account{AccessToken: acc.AccessToken, OID: acc.OID, TID: acc.TID, Proxy: acc.Proxy}
	// The stream is opened by the actual response path below. Do not emit a
	// tool preamble here: a request may contain tools in its schema while still
	// being an ordinary text question.
	streamPrimed := false
	// Streaming requests must not wait for the synchronous tool router. This
	// path forwards ordinary upstream text deltas immediately; tool routing for
	// non-streaming requests remains below until the event-level tool protocol
	// is available end-to-end.
	if body.Stream && len(toolMaps) > 0 && fmt.Sprint(body.ToolChoice) != "none" {
		// Preserve the existing validated tool router for streaming tool turns.
		// Only fall through to text streaming when the router explicitly selects
		// no tool; this prevents a natural-language preamble from becoming a
		// completed assistant turn with the actual call lost.
		routePrompt := modelToolRouterPrompt(prompt+"\n"+ledger.RouterContext(), toolMaps, body.ToolChoice)
		routeRes, routeErr := s.chat.Chat(ctx, account, chathub.Request{Text: routePrompt, Tone: tone})
		if routeErr != nil {
			http.Error(w, "tool router: "+routeErr.Error(), http.StatusBadGateway)
			return
		}
		calls, parsed := parseModelToolDecision(routeRes.Text, toolMaps, body.ToolChoice)
		if !parsed {
			repairRes, repairErr := s.chat.Chat(ctx, account, chathub.Request{Text: `Repair this tool routing output into JSON only with shape {"calls":[{"name":"function_name","arguments":{}}]}. Use {"calls":[]} if no tool is needed. OUTPUT:\n` + compactToolResult(routeRes.Text, 6000), Tone: tone})
			if repairErr == nil {
				calls, parsed = parseModelToolDecision(repairRes.Text, toolMaps, body.ToolChoice)
			}
		}
		if parsed && len(calls) > 0 {
			scope := fmt.Sprintf("%d:%v:stream", len(body.Messages), completedCallIDs(ledger))
			for i := range calls {
				calls[i].ID = scopedCallID(calls[i].Name, string(calls[i].Arguments), i, scope)
			}
			calls = limitToolCalls(calls, configuredToolCallLimit(s.settings))
			if body.SessionKey != "" {
				s.sessions.upsert(conversation{ID: body.SessionKey, AccountID: acc.ID, ConversationID: routeRes.ConversationID, SessionID: routeRes.SessionID, Title: prompt})
			}
			_ = writeToolResponse(w, "chatcmpl-"+uuid.NewString(), firstNonEmpty(body.Model, "m365-copilot"), true, calls, routeRes)
			return
		}
	}
	if body.Stream {
		answerPrompt := prompt + "\n" + ledger.RouterContext() + "\nFINAL ANSWER RULE: Answer the user directly. If a tool is explicitly required, emit its structured call; otherwise return ordinary text."
		answerReq := chathub.Request{Text: answerPrompt, Tone: tone, ConversationID: body.ConversationID, SessionID: body.SessionID, Attachments: body.Attachments, Tools: body.Tools, ToolChoice: body.ToolChoice}
		id := "chatcmpl-" + uuid.NewString()
		model := firstNonEmpty(body.Model, "m365-copilot")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		if err := sseRaw(r.Context(), w, flusher, ": connected\n\n"); err != nil {
			return
		}
		first := true
		var streamedTools []detectedToolCall
		res2, err := s.chat.ChatWithEvents(ctx, account, answerReq, func(ev chathub.StreamEvent) error {
			if ev.Kind == "tool" && ev.ToolName != "" && len(ev.Arguments) > 0 {
				streamedTools = append(streamedTools, detectedToolCall{ID: "call_" + uuid.NewString(), Name: ev.ToolName, Arguments: ev.Arguments})
				return nil
			}
			if ev.Kind != "text" || ev.Text == "" {
				return nil
			}
			delta := map[string]any{"content": ev.Text}
			if first {
				delta["role"] = "assistant"
				first = false
			}
			chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}}
			if err := sseRaw(r.Context(), w, flusher, "data: "+mustJSON(chunk)+"\n\n"); err != nil {
				return err
			}
			return nil
		})
		if err == nil {
			for i, tc := range streamedTools {
				chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": i, "id": tc.ID, "type": "function", "function": map[string]any{"name": tc.Name, "arguments": string(tc.Arguments)}}}}, "finish_reason": nil}}}
				if err := sseRaw(r.Context(), w, flusher, "data: "+mustJSON(chunk)+"\n\n"); err != nil {
					return
				}
			}
			if err := sseRaw(r.Context(), w, flusher, "data: [DONE]\n\n"); err != nil {
				return
			}
			in, out := estimateChatUsage(firstNonEmpty(body.Model, "m365-copilot"), body.Messages, body.Tools, res2.FullText)
			s.addTokens(acc.ID, in, out)
		}
		return
	}
	// Ask the upstream model to select and validate the next tool. The gateway
	// remains tool-agnostic; it only validates and serializes the decision.
	if len(toolMaps) > 0 && fmt.Sprint(body.ToolChoice) != "none" {
		routePrompt := modelToolRouterPrompt(prompt+"\n"+ledger.RouterContext(), toolMaps, body.ToolChoice)
		routeRes, routeErr := s.chat.Chat(ctx, account, chathub.Request{Text: routePrompt, Tone: tone})
		if routeErr != nil {
			http.Error(w, "tool router: "+routeErr.Error(), http.StatusBadGateway)
			return
		}
		calls, parsed := parseModelToolDecision(routeRes.Text, toolMaps, body.ToolChoice)
		if !parsed {
			repairRes, repairErr := s.chat.Chat(ctx, account, chathub.Request{Text: `Repair this tool routing output into JSON only with shape {"calls":[{"name":"function_name","arguments":{}}]}. Do not invent calls; use {"calls":[]} if unrecoverable. OUTPUT:
` + compactToolResult(routeRes.Text, 6000), Tone: tone})
			if repairErr == nil {
				calls, parsed = parseModelToolDecision(repairRes.Text, toolMaps, body.ToolChoice)
			}
			if !parsed {
				http.Error(w, "model returned an invalid tool routing decision", http.StatusBadGateway)
				return
			}
		}
		if len(calls) > 0 {
			scope := fmt.Sprintf("%d:%v", len(body.Messages), completedCallIDs(ledger))
			for i := range calls {
				calls[i].ID = scopedCallID(calls[i].Name, string(calls[i].Arguments), i, scope)
			}
			calls = limitToolCalls(calls, configuredToolCallLimit(s.settings))
			_ = writeToolResponse(w, "chatcmpl-"+uuid.NewString(), firstNonEmpty(body.Model, "m365-copilot"), body.Stream, calls, routeRes, streamPrimed)
			return
		}
		if fmt.Sprint(body.ToolChoice) == "required" {
			defs, _ := json.Marshal(toolMaps)
			retryText := `Select at least one required next tool call from FUNCTION_DEFINITIONS. Validate every argument against its schema. Return JSON only as {"calls":[{"name":"function_name","arguments":{}}]}.
APPLICATION_REQUEST_AND_EVIDENCE:
` + prompt + "\n" + ledger.RouterContext() + "\nFUNCTION_DEFINITIONS:\n" + string(defs)
			retryRes, retryErr := s.chat.Chat(ctx, account, chathub.Request{Text: retryText, Tone: tone})
			if retryErr == nil {
				calls, parsed = parseModelToolDecision(retryRes.Text, toolMaps, body.ToolChoice)
				if parsed && len(calls) > 0 {
					scope := fmt.Sprintf("%d:%v:required-retry", len(body.Messages), completedCallIDs(ledger))
					for i := range calls {
						calls[i].ID = scopedCallID(calls[i].Name, string(calls[i].Arguments), i, scope)
					}
					calls = limitToolCalls(calls, configuredToolCallLimit(s.settings))
					_ = writeToolResponse(w, "chatcmpl-"+uuid.NewString(), firstNonEmpty(body.Model, "m365-copilot"), body.Stream, calls, retryRes, streamPrimed)
					return
				}
			}
			http.Error(w, "model did not select a required tool after constrained retry", http.StatusBadGateway)
			return
		}
	}
	answerPrompt := prompt + "\n" + ledger.RouterContext() + "\nFINAL ANSWER RULE: Report only actions supported by completed tool results. If the goal is not fully verified, state exactly what remains unconfirmed."
	answerReq := chathub.Request{Text: answerPrompt, Tone: tone, ConversationID: body.ConversationID, SessionID: body.SessionID, Attachments: body.Attachments}
	var res chathub.Result
	streamed := false
	if body.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}
		id := "chatcmpl-" + uuid.NewString()
		model := firstNonEmpty(body.Model, "m365-copilot")
		firstDelta := true
		emit := func(content string) error {
			delta := map[string]any{"content": content}
			if firstDelta {
				firstDelta = false
				delta = map[string]any{"content": nil, "reasoning_content": "正在分析请求并准备回答……"}
			}
			chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model, "choices": []map[string]any{{"index": 0, "delta": delta}}}
			if err := sseRaw(r.Context(), w, flusher, "data: "+mustJSON(chunk)+"\n\n"); err != nil {
				return err
			}
			streamed = true
			return nil
		}
		// Commit headers immediately; the first upstream delta is then forwarded
		// without waiting for the full ChatHub completion frame.
		if err := sseRaw(r.Context(), w, flusher, ": connected\n\n"); err != nil {
			return
		}
		res, err = s.chat.ChatWithDelta(ctx, account, answerReq, emit)
		if err == nil {
			if err := sseRaw(r.Context(), w, flusher, "data: [DONE]\n\n"); err != nil {
				return
			}
		}
	} else {
		res, err = s.chat.Chat(ctx, account, answerReq)
	}
	if err != nil {
		s.markAccountResult(acc.ID, err)
		if streamed {
			return
		}
		// non-streaming auto-selected chats fail over to the next healthy account once
		if !body.Stream && body.AccountID == "" && (IsRateLimited(err) || IsAuthFailure(err)) {
			if next, nerr := s.nextHealthyAccount(acc.ID); nerr == nil {
				acc = next
				account = chathub.Account{AccessToken: acc.AccessToken, OID: acc.OID, TID: acc.TID, Proxy: acc.Proxy}
				var rerr error
				res, rerr = s.chat.Chat(ctx, account, chathub.Request{
					Text:           answerPrompt,
					Tone:           tone,
					ConversationID: body.ConversationID,
					SessionID:      body.SessionID,
					Attachments:    body.Attachments,
				})
				if rerr == nil {
					s.markAccountResult(acc.ID, nil)
					err = nil
				} else {
					err = rerr
				}
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	s.markAccountResult(acc.ID, nil)
	in, out := estimateChatUsage(firstNonEmpty(body.Model, "m365-copilot"), body.Messages, body.Tools, res.FullText)
	s.addTokens(acc.ID, in, out)
	if res.Throttling != nil {
		s.healthPool().MarkRateLimited(acc.ID, time.Time{})
	}
	if body.Stream {
		return
	}

	if body.SessionKey != "" {
		s.sessions.upsert(conversation{ID: body.SessionKey, AccountID: acc.ID, ConversationID: res.ConversationID, SessionID: res.SessionID, Title: prompt})
	}
	model := body.Model
	if model == "" {
		model = "m365-copilot"
	}
	id := "chatcmpl-" + uuid.NewString()
	if calls := fencedToolCalls(res.Text, toolMaps, body.ToolChoice); len(calls) > 0 {
		calls = limitToolCalls(calls, configuredToolCallLimit(s.settings))
		_ = writeToolResponse(w, id, model, body.Stream, calls, res)
		return
	}
	if calls := nativeToolCalls(res.Events, body.Tools); len(calls) > 0 {
		calls = limitToolCalls(calls, configuredToolCallLimit(s.settings))
		_ = writeToolResponse(w, id, model, body.Stream, calls, res)
		return
	}
	if !completionEvidenceAllows(res.Text, ledger) {
		res.Text = "I cannot confirm completion because no matching tool results were returned. No external action has been verified."
	}
	created := time.Now().Unix()

	if body.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}
		// one-shot "stream" — emit full content then done
		chunk := map[string]any{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{
				"index": 0,
				"delta": map[string]any{"role": "assistant", "content": res.Text},
			}},
		}
		b, _ := json.Marshal(chunk)
		if err := sseRaw(r.Context(), w, flusher, "data: "+string(b)+"\n\n"); err != nil {
			return
		}
		if err := sseRaw(r.Context(), w, flusher, "data: [DONE]\n\n"); err != nil {
			return
		}
		return
	}

	content := any(res.Text)
	if len(res.Images) > 0 {
		parts := []any{map[string]any{"type": "text", "text": res.Text}}
		for _, u := range res.Images {
			parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]any{"url": u}})
		}
		content = parts
	}
	jsonOut(w, map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": content,
			},
			"finish_reason": "stop",
		}},
		"m365": compatM365Metadata(res),
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func extractOIDTID(accessToken string) (oid, tid string) {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", ""
	}
	if v, ok := m["oid"].(string); ok {
		oid = v
	}
	if v, ok := m["tid"].(string); ok {
		tid = v
	}
	return oid, tid
}

// --- per-account 429 failover (D 项) ---

// health returns the per-account health tracker, initializing it once.
func (s *Server) healthPool() *accountHealth {
	s.accountPoolOnce.Do(func() { s.accountPool = newAccountHealth() })
	return s.accountPool
}

// nextHealthyAccount returns the next available account that is not avoidID and
// not currently rate-limited or auth-failed.
func (s *Server) nextHealthyAccount(avoidID string) (auth.AccountToken, error) {
	list := s.tokens.List()
	pool := s.healthPool()
	for _, acc := range list {
		if acc.ID == avoidID {
			continue
		}
		if !pool.Available(acc.ID) {
			continue
		}
		tok, err := s.tokens.EnsureValid(acc.ID)
		if err == nil {
			return tok, nil
		}
	}
	return auth.AccountToken{}, fmt.Errorf("no healthy account available")
}

// markAccountResult updates per-account health from a chat result/error.
func (s *Server) markAccountResult(id string, err error) {
	if err == nil {
		s.healthPool().MarkSuccess(id)
		return
	}
	if IsRateLimited(err) {
		s.healthPool().MarkRateLimited(id, time.Time{})
		return
	}
	if IsAuthFailure(err) {
		s.healthPool().MarkAuthFail(id)
		return
	}
}
