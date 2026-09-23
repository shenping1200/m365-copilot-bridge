package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

type Kind string

const (
	KindDirect Kind = "direct"
	KindHTTP   Kind = "http"
	KindSOCKS5 Kind = "socks5"
	KindSOCKS4 Kind = "socks4"
)

type Config struct {
	Raw  string
	Type Kind
	Host string
	Port string
	User string
	Pass string
	// UseTLS is true when the user wrote `https://` for the proxy URL.
	// Many proxy providers label their service as "HTTPS" while the proxy
	// itself accepts plain HTTP CONNECT — but real TLS-wrapped proxies do
	// exist (e.g. 12.180.8.60:443). We honor the scheme so users can pick
	// whichever the provider actually runs. This only affects how Go dials
	// the proxy host; HTTP CONNECT itself is sent as plaintext in both
	// cases, then TLS is layered on top for the target host.
	UseTLS bool
}

// Parse 识别以下格式：
//
//	http(s)://[user:pass@]host:port           (标准)
//	http(s)://host:port:user:pass             (非标准, 部分代理服务商常用)
//	socks5://[user:pass@]host:port          (标准)
//	socks5://host:port:user:pass            (非标准, 部分代理服务商常用)
//	socks5h://host:port                      (远程解析 DNS)
//	socks4://[user:pass@]host:port
//	host:port                                (无 scheme, 默认按 socks5)
func Parse(raw string) (Config, error) {
	raw = strings.TrimSpace(raw)
	c := Config{Raw: raw}
	if raw == "" {
		c.Type = KindDirect
		return c, nil
	}
	low := strings.ToLower(raw)
	if i := strings.Index(low, "://"); i > 0 {
		scheme := low[:i]
		rest := raw[i+3:]
		switch scheme {
		case "http":
			c.Type = KindHTTP
			c.UseTLS = false
			return parseAuthHostPort(c, rest)
		case "https":
			c.Type = KindHTTP
			c.UseTLS = true
			return parseAuthHostPort(c, rest)
		case "socks5", "socks5h":
			c.Type = KindSOCKS5
			return parseSocks(c, rest)
		case "socks4":
			c.Type = KindSOCKS4
			return parseSocks(c, rest)
		default:
			return c, fmt.Errorf("不支持的代理协议: %q", scheme)
		}
	}
	// 无 scheme: 默认 socks5
	c.Type = KindSOCKS5
	return parseSocks(c, raw)
}

func parseSocks(c Config, rest string) (Config, error) {
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		// 标准: user:pass@host:port
		authPart := rest[:at]
		hp := rest[at+1:]
		if co := strings.Index(authPart, ":"); co >= 0 {
			c.User = authPart[:co]
			c.Pass = authPart[co+1:]
		} else {
			c.User = authPart
		}
		return setHostPort(c, hp)
	}
	// 非标准: host:port:user:pass (恰好 4 段, 无 @)
	parts := strings.Split(rest, ":")
	if len(parts) == 4 {
		c.Host, c.Port, c.User, c.Pass = parts[0], parts[1], parts[2], parts[3]
		return c, nil
	}
	if len(parts) == 2 {
		c.Host, c.Port = parts[0], parts[1]
		return c, nil
	}
	return c, fmt.Errorf("无法解析 SOCKS 代理地址: %q", rest)
}

func parseAuthHostPort(c Config, rest string) (Config, error) {
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		authPart := rest[:at]
		hp := rest[at+1:]
		if co := strings.Index(authPart, ":"); co >= 0 {
			c.User = authPart[:co]
			c.Pass = authPart[co+1:]
		} else {
			c.User = authPart
		}
		return setHostPort(c, hp)
	}
	// 无 @: 支持非标准 4 段 host:port:user:pass (与 SOCKS 分支一致)。
	// 例如 https://172.87.24.55:443:123:123
	if parts := strings.Split(rest, ":"); len(parts) == 4 {
		c.Host, c.Port, c.User, c.Pass = parts[0], parts[1], parts[2], parts[3]
		return c, nil
	}
	return setHostPort(c, rest)
}

func setHostPort(c Config, hp string) (Config, error) {
	if co := strings.LastIndex(hp, ":"); co >= 0 {
		c.Host = hp[:co]
		c.Port = hp[co+1:]
	} else {
		c.Host = hp
	}
	if c.Host == "" {
		return c, fmt.Errorf("代理地址缺少 host")
	}
	return c, nil
}

func (c Config) addr() string { return net.JoinHostPort(c.Host, c.Port) }

// proxyURL builds the URL Go's http transport / gorilla dialer uses to reach
// the proxy. The scheme follows the user's input: http:// → plaintext dial
// (CONNECT in HTTP), https:// → TLS dial (CONNECT over TLS). Real-world
// "HTTPS" proxies that listen on TCP/443 with TLS to the client honor this;
// providers that just label their CONNECT endpoint "HTTPS" should be entered
// as http:// instead.
func (c Config) proxyURL() *url.URL {
	u := url.URL{Scheme: "http", Host: c.addr()}
	if c.UseTLS {
		u.Scheme = "https"
	}
	if c.User != "" {
		u.User = url.UserPassword(c.User, c.Pass)
	}
	return &u
}

// tunnelDialContext opens a connection to the *target* addr by first
// establishing a tunnel through the HTTP/HTTPS proxy. The proxy connection is
// dialed with InsecureSkipVerify (we trust the user's proxy cert, expired or
// self-signed — matching how fingerprint browsers behave); the target host's
// own TLS is negotiated on top of the tunnel and verified by the caller's
// transport/dialer config.
func (c Config) tunnelDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var conn net.Conn
	var err error
	proxyAddr := c.addr()
	if c.UseTLS {
		d := tls.Dialer{
			NetDialer: &net.Dialer{},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
		conn, err = d.DialContext(ctx, "tcp", proxyAddr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s 失败: %w", proxyAddr, err)
	}

	// Send HTTP CONNECT to the proxy.
	req, err := http.NewRequest(http.MethodConnect, "http://"+addr, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Pass)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("写入代理 CONNECT 失败: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取代理响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("代理拒绝 CONNECT: %s", resp.Status)
	}
	return conn, nil
}

func (c Config) socksAuth() *proxy.Auth {
	if c.User == "" {
		return nil
	}
	return &proxy.Auth{User: c.User, Password: c.Pass}
}

// HTTPClient 返回带代理的 *http.Client (直连返回 DefaultClient)。
func (c Config) HTTPClient() (*http.Client, error) {
	if c.Type == KindDirect {
		return http.DefaultClient, nil
	}
	switch c.Type {
	case KindHTTP:
		// Tunnel through the proxy via a custom DialContext. The proxy leg
		// is dialed with InsecureSkipVerify (fingerprint browsers do the same
		// — they trust the user's proxy cert, even if it's self-signed or
		// expired). The target host's TLS is still verified normally by the
		// transport's default TLSClientConfig.
		return &http.Client{
			Transport: &http.Transport{
				DialContext:       c.tunnelDialContext,
				Proxy:             nil,
				DisableKeepAlives: false,
			},
			Timeout: 30 * time.Second,
		}, nil
	case KindSOCKS5, KindSOCKS4:
		d, err := proxy.SOCKS5("tcp", c.addr(), c.socksAuth(), proxy.Direct)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return d.Dial(network, addr)
				},
			},
			Timeout: 30 * time.Second,
		}, nil
	}
	return http.DefaultClient, nil
}

// WebSocketDialer 在 base 基础上注入代理, 返回新的 gorilla Dialer (不修改 base)。
func (c Config) WebSocketDialer(base *websocket.Dialer) (*websocket.Dialer, error) {
	d := *base
	if c.Type == KindDirect {
		return &d, nil
	}
	switch c.Type {
	case KindHTTP:
		// Tunnel through the proxy ourselves (same as HTTPClient) so the
		// proxy leg can use InsecureSkipVerify while the target WS TLS is
		// still verified by gorilla. Clear d.Proxy to avoid double CONNECT.
		d.Proxy = nil
		d.NetDialContext = c.tunnelDialContext
	case KindSOCKS5, KindSOCKS4:
		sd, err := proxy.SOCKS5("tcp", c.addr(), c.socksAuth(), proxy.Direct)
		if err != nil {
			return nil, err
		}
		d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sd.Dial(network, addr)
		}
	}
	return &d, nil
}

// HTTPClientFor 便捷封装: 直接传原始代理串。
func HTTPClientFor(raw string) (*http.Client, error) {
	c, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return c.HTTPClient()
}

// WebSocketDialerFor 便捷封装: 直接传原始代理串。
func WebSocketDialerFor(base *websocket.Dialer, raw string) (*websocket.Dialer, error) {
	c, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return c.WebSocketDialer(base)
}
