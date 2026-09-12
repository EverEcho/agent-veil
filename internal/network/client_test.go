package network

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/security"
)

func TestRedirectTargetIsRevalidated(t *testing.T) {
	allowlist, _ := security.NewUpstreamAllowlist([]domain.Upstream{{Scheme: "https", Host: "api.example", Port: 443}})
	client := NewHTTPClient(nil, allowlist)
	allowed, _ := url.Parse("https://api.example/next")
	denied, _ := url.Parse("https://evil.example/next")
	if err := client.CheckRedirect(&http.Request{URL: allowed}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(&http.Request{URL: denied}, nil); err == nil {
		t.Fatal("redirect escaped allowlist")
	}
}

func TestRedirectFailsClosedWithoutAllowlist(t *testing.T) {
	client := NewHTTPClient(nil, nil)
	target, _ := url.Parse("https://api.example/next")
	if err := client.CheckRedirect(&http.Request{URL: target}, nil); err == nil {
		t.Fatal("redirect was accepted without an allowlist")
	}
}

func TestNetworkRouteTransportsAreExplicit(t *testing.T) {
	direct, err := NewTransport(domain.NetworkRoute{Type: domain.NetworkDirect})
	if err != nil || direct.Proxy != nil {
		t.Fatalf("direct route inherited a proxy: %v", err)
	}
	system, err := NewTransport(domain.NetworkRoute{Type: domain.NetworkSystemProxy})
	if err != nil || system.Proxy == nil {
		t.Fatalf("system proxy was not configured: %v", err)
	}
	httpProxy, err := NewTransport(domain.NetworkRoute{Type: domain.NetworkHTTPProxy, Endpoint: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	requestURL, _ := url.Parse("https://api.example/v1")
	proxyURL, err := httpProxy.Proxy(&http.Request{URL: requestURL})
	if err != nil || proxyURL.String() != "http://127.0.0.1:8080" {
		t.Fatalf("proxy=%v err=%v", proxyURL, err)
	}
	for _, route := range []domain.NetworkRoute{
		{Type: domain.NetworkDirect, Endpoint: "http://127.0.0.1:8080"},
		{Type: domain.NetworkHTTPProxy, Endpoint: "http://user:secret@127.0.0.1:8080"},
		{Type: domain.NetworkSOCKS5, Endpoint: "http://127.0.0.1:1080"},
	} {
		if _, err := NewTransport(route); err == nil {
			t.Fatalf("invalid route accepted: %+v", route)
		}
	}
}

func TestSOCKS5DialerNegotiatesDomainTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan string, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- "accept: " + acceptErr.Error()
			return
		}
		defer connection.Close()
		greeting := make([]byte, 3)
		if _, readErr := io.ReadFull(connection, greeting); readErr != nil || string(greeting) != string([]byte{5, 1, 0}) {
			serverResult <- "invalid greeting"
			return
		}
		_, _ = connection.Write([]byte{5, 0})
		header := make([]byte, 5)
		if _, readErr := io.ReadFull(connection, header); readErr != nil || header[0] != 5 || header[1] != 1 || header[3] != 3 {
			serverResult <- "invalid connect request"
			return
		}
		host := make([]byte, int(header[4]))
		port := make([]byte, 2)
		_, hostErr := io.ReadFull(connection, host)
		_, portErr := io.ReadFull(connection, port)
		if hostErr != nil || portErr != nil || string(host) != "api.example" || string(port) != string([]byte{1, 187}) {
			serverResult <- "wrong target"
			return
		}
		_, _ = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 4, 56})
		serverResult <- "ok"
	}()
	dialer := socks5Dialer{address: listener.Addr().String(), dialer: &net.Dialer{Timeout: time.Second}}
	connection, err := dialer.DialContext(context.Background(), "tcp", "api.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if result := <-serverResult; result != "ok" {
		t.Fatal(result)
	}
}
