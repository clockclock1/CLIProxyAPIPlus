// Package executor provides runtime execution capabilities for various AI service providers.
// This file implements a custom HTTP transport for Codex using utls to match Chrome/Node.js TLS fingerprint.
package executor

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// codexUtlsRoundTripper implements http.RoundTripper using utls with Chrome fingerprint
// to match the TLS fingerprint of official OpenAI Node SDK clients.
type codexUtlsRoundTripper struct {
	mu          sync.Mutex
	connections map[string]*http2.ClientConn
	pending     map[string]*sync.Cond
	dialer      proxy.Dialer
}

// newCodexUtlsRoundTripper creates a new utls-based round tripper for Codex with optional proxy support.
func newCodexUtlsRoundTripper(cfg *config.Config, auth interface{}) *codexUtlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	
	// Configure proxy if available
	var proxyURL string
	if cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Debugf("codex: failed to configure proxy dialer: %v", errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	return &codexUtlsRoundTripper{
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*sync.Cond),
		dialer:      dialer,
	}
}

// getOrCreateConnection gets an existing HTTP/2 connection or creates a new one.
func (t *codexUtlsRoundTripper) getOrCreateConnection(host, addr string) (*http2.ClientConn, error) {
	t.mu.Lock()

	// Check if connection exists and is usable
	if h2Conn, ok := t.connections[host]; ok && h2Conn.CanTakeNewRequest() {
		t.mu.Unlock()
		return h2Conn, nil
	}

	// Check if another goroutine is already creating a connection
	if cond, ok := t.pending[host]; ok {
		cond.Wait()
		if h2Conn, ok := t.connections[host]; ok && h2Conn.CanTakeNewRequest() {
			t.mu.Unlock()
			return h2Conn, nil
		}
	}

	// Mark this host as pending
	cond := sync.NewCond(&t.mu)
	t.pending[host] = cond
	t.mu.Unlock()

	// Create connection outside the lock
	h2Conn, err := t.createConnection(host, addr)

	t.mu.Lock()
	defer t.mu.Unlock()

	// Remove pending marker and wake up waiting goroutines
	delete(t.pending, host)
	cond.Broadcast()

	if err != nil {
		return nil, err
	}

	// Store the new connection
	t.connections[host] = h2Conn
	return h2Conn, nil
}

// createConnection creates a new HTTP/2 connection with Chrome TLS fingerprint.
// This matches the TLS fingerprint of Node.js/OpenSSL used by the official OpenAI SDK.
func (t *codexUtlsRoundTripper) createConnection(host, addr string) (*http2.ClientConn, error) {
	conn, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Use Chrome Auto fingerprint which closely matches Node.js/OpenSSL behavior
	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}
	
	tlsConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	// Create HTTP/2 transport
	tr := &http2.Transport{
		// Allow HTTP/2 connection reuse
		AllowHTTP: false,
		// Disable compression for better compatibility
		DisableCompression: false,
	}
	
	h2Conn, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return h2Conn, nil
}

// RoundTrip implements http.RoundTripper
func (t *codexUtlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	hostname := req.URL.Hostname()

	h2Conn, err := t.getOrCreateConnection(hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		// Connection failed, remove it from cache
		t.mu.Lock()
		if cached, ok := t.connections[hostname]; ok && cached == h2Conn {
			delete(t.connections, hostname)
		}
		t.mu.Unlock()
		return nil, err
	}

	return resp, nil
}

// codexStandardRoundTripper implements a standard HTTP transport with optimized settings
// for OpenAI API requests. This is used as a fallback when utls is not needed.
type codexStandardRoundTripper struct {
	transport *http.Transport
}

// newCodexStandardRoundTripper creates a standard HTTP transport with settings
// optimized for OpenAI API requests.
func newCodexStandardRoundTripper(cfg *config.Config) *codexStandardRoundTripper {
	transport := &http.Transport{
		// Connection pooling settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		
		// Timeouts
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		
		// Enable HTTP/2
		ForceAttemptHTTP2: true,
		
		// TLS configuration
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		},
		
		// Dial settings
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	
	// Configure proxy if available
	if cfg != nil && cfg.ProxyURL != "" {
		if proxyTransport, _, err := proxyutil.BuildHTTPTransport(cfg.ProxyURL); err == nil && proxyTransport != nil {
			return &codexStandardRoundTripper{transport: proxyTransport}
		}
	}
	
	return &codexStandardRoundTripper{transport: transport}
}

// RoundTrip implements http.RoundTripper
func (t *codexStandardRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}

// newCodexHTTPClient creates an HTTP client optimized for OpenAI Codex requests.
// It uses utls for TLS fingerprint matching when connecting to chatgpt.com domains.
func newCodexHTTPClient(cfg *config.Config, auth interface{}, useUtls bool) *http.Client {
	if useUtls {
		return &http.Client{
			Transport: newCodexUtlsRoundTripper(cfg, auth),
			Timeout:   0, // No timeout, handled by context
		}
	}
	
	return &http.Client{
		Transport: newCodexStandardRoundTripper(cfg).transport,
		Timeout:   0, // No timeout, handled by context
	}
}

// shouldUseUtlsForCodex determines if utls should be used for the given URL.
// utls is used for chatgpt.com domains to match Chrome/Node.js TLS fingerprint.
func shouldUseUtlsForCodex(url string) bool {
	return strings.Contains(url, "chatgpt.com") || strings.Contains(url, "openai.com")
}


// newCodexWebsocketDialer creates a WebSocket dialer with TLS fingerprint matching.
// For chatgpt.com domains, it uses utls to match Chrome/Node.js TLS fingerprint.
func newCodexWebsocketDialer(cfg *config.Config, auth interface{}, wsURL string) *websocket.Dialer {
	useUtls := shouldUseUtlsForCodex(wsURL)
	
	dialer := &websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  30 * time.Second,
		EnableCompression: true,
		NetDialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	
	// Configure TLS for utls fingerprint matching
	if useUtls {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			// Additional TLS settings to match Node.js/OpenSSL behavior
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		}
	}
	
	// Configure proxy if available
	var proxyURL string
	if cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	
	if proxyURL != "" {
		setting, errParse := proxyutil.Parse(proxyURL)
		if errParse != nil {
			log.Debugf("codex websocket: failed to parse proxy URL: %v", errParse)
			return dialer
		}

		switch setting.Mode {
		case proxyutil.ModeDirect:
			dialer.Proxy = nil
		case proxyutil.ModeProxy:
			switch setting.URL.Scheme {
			case "socks5":
				var proxyAuth *proxy.Auth
				if setting.URL.User != nil {
					username := setting.URL.User.Username()
					password, _ := setting.URL.User.Password()
					proxyAuth = &proxy.Auth{User: username, Password: password}
				}
				socksDialer, errSOCKS5 := proxy.SOCKS5("tcp", setting.URL.Host, proxyAuth, proxy.Direct)
				if errSOCKS5 != nil {
					log.Debugf("codex websocket: failed to create SOCKS5 dialer: %v", errSOCKS5)
					return dialer
				}
				dialer.Proxy = nil
				dialer.NetDialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
					return socksDialer.Dial(network, addr)
				}
			case "http", "https":
				dialer.Proxy = http.ProxyURL(setting.URL)
			default:
				log.Debugf("codex websocket: unsupported proxy scheme: %s", setting.URL.Scheme)
			}
		}
	}
	
	return dialer
}
