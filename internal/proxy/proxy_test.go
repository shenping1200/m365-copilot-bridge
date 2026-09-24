package proxy

import (
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// TestParse covers every documented proxy format plus the error branches.
// Parse is pure string parsing with no network access, so this is a fast
// unit test that exercises the full parse matrix.
func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantErr   bool
		errSubstr string
		typ       Kind
		host      string
		port      string
		user      string
		pass      string
		useTLS    bool
	}{
		// direct
		{"empty -> direct", "", false, "", KindDirect, "", "", "", "", false},
		{"whitespace only -> direct", "   ", false, "", KindDirect, "", "", "", "", false},

		// http(s) standard with auth
		{"http standard with auth", "http://u:p@1.2.3.4:8080", false, "", KindHTTP, "1.2.3.4", "8080", "u", "p", false},
		{"https standard with auth", "https://u:p@1.2.3.4:8080", false, "", KindHTTP, "1.2.3.4", "8080", "u", "p", true},

		// http(s) no auth
		{"http no auth", "http://1.2.3.4:8080", false, "", KindHTTP, "1.2.3.4", "8080", "", "", false},
		{"https no auth", "https://1.2.3.4:443", false, "", KindHTTP, "1.2.3.4", "443", "", "", true},

		// http(s) non-standard 4-part host:port:user:pass (some providers)
		{"https 4-part nonstandard", "https://172.87.24.55:443:123:123", false, "", KindHTTP, "172.87.24.55", "443", "123", "123", true},

		// socks5 standard with auth
		{"socks5 standard with auth", "socks5://u:p@1.2.3.4:1080", false, "", KindSOCKS5, "1.2.3.4", "1080", "u", "p", false},
		// socks5 non-standard 4-part
		{"socks5 nonstandard 4-part", "socks5://1.2.3.4:1080:user:pass", false, "", KindSOCKS5, "1.2.3.4", "1080", "user", "pass", false},
		// socks5h remote DNS resolution
		{"socks5h remote dns", "socks5h://1.2.3.4:1080", false, "", KindSOCKS5, "1.2.3.4", "1080", "", "", false},
		// socks4 standard with auth
		{"socks4 unsupported -> error", "socks4://u:p@1.2.3.4:1080", true, "暂不支持 SOCKS4", "", "", "", "", "", false},
		// no scheme defaults to socks5
		{"no scheme defaults socks5", "1.2.3.4:1080", false, "", KindSOCKS5, "1.2.3.4", "1080", "", "", false},

		// error branches
		{"unsupported scheme", "ftp://1.2.3.4:1080", true, "不支持的代理协议", "", "", "", "", "", false},
		{"socks5 empty after scheme", "socks5://", true, "无法解析 SOCKS", "", "", "", "", "", false},
		{"http missing host", "http://", true, "缺少 host", "", "", "", "", "", false},
		{"socks5 host only no port", "socks5://1.2.3.4", true, "无法解析 SOCKS", "", "", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(tt.raw)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (config=%+v)", c)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Type != tt.typ {
				t.Errorf("Type = %q, want %q", c.Type, tt.typ)
			}
			if c.Host != tt.host {
				t.Errorf("Host = %q, want %q", c.Host, tt.host)
			}
			if c.Port != tt.port {
				t.Errorf("Port = %q, want %q", c.Port, tt.port)
			}
			if c.User != tt.user {
				t.Errorf("User = %q, want %q", c.User, tt.user)
			}
			if c.Pass != tt.pass {
				t.Errorf("Pass = %q, want %q", c.Pass, tt.pass)
			}
			if c.UseTLS != tt.useTLS {
				t.Errorf("UseTLS = %v, want %v", c.UseTLS, tt.useTLS)
			}
			if c.Raw != strings.TrimSpace(tt.raw) {
				t.Errorf("Raw = %q, want %q", c.Raw, strings.TrimSpace(tt.raw))
			}
		})
	}
}

// TestProxyURLAndClientsSmoke verifies the derived helpers (proxyURL scheme,
// direct client identity, error propagation) without making any network call.
func TestProxyURLAndClientsSmoke(t *testing.T) {
	c, err := Parse("https://u:p@1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	u := c.proxyURL()
	if u.Scheme != "https" {
		t.Errorf("proxyURL scheme = %q, want https", u.Scheme)
	}
	if u.Host != "1.2.3.4:8080" {
		t.Errorf("proxyURL host = %q, want 1.2.3.4:8080", u.Host)
	}
	if u.User == nil || u.User.Username() != "u" {
		t.Errorf("proxyURL user = %v, want u", u.User)
	}

	// direct client must carry a timeout so an unresponsive upstream cannot
	// block forever (http.DefaultClient has Timeout=0 = wait forever).
	dcCfg, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	dc, err := dcCfg.HTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	if dc.Timeout <= 0 {
		t.Errorf("direct HTTPClient 缺超时保护 (Timeout=%v): 上游挂住会永久等待", dc.Timeout)
	}

	// error from Parse must propagate through the convenience wrappers
	if _, err := HTTPClientFor("ftp://x:1"); err == nil {
		t.Errorf("HTTPClientFor should error on unsupported scheme")
	}
	if _, err := WebSocketDialerFor(&websocket.Dialer{}, "ftp://x:1"); err == nil {
		t.Errorf("WebSocketDialerFor should error on unsupported scheme")
	}
}
