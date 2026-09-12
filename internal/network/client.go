package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/security"
)

func NewHTTPClient(transport http.RoundTripper, allowlist *security.UpstreamAllowlist) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(request *http.Request, _ []*http.Request) error { return allowlist.ValidateURL(request.URL) }}
}

func NewTransport(route domain.NetworkRoute) (*http.Transport, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	switch route.Type {
	case domain.NetworkDirect:
		if route.Endpoint != "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "configure network route", "direct route cannot have an endpoint")
		}
	case domain.NetworkSystemProxy:
		if route.Endpoint != "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "configure network route", "system proxy route cannot have an endpoint")
		}
		transport.Proxy = http.ProxyFromEnvironment
	case domain.NetworkHTTPProxy:
		proxyURL, err := parseProxyEndpoint(route.Endpoint, "http", "https")
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	case domain.NetworkSOCKS5:
		proxyURL, err := parseProxyEndpoint(route.Endpoint, "socks5")
		if err != nil {
			return nil, err
		}
		dialer := socks5Dialer{address: proxyURL.Host, dialer: &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}}
		transport.DialContext = dialer.DialContext
	default:
		return nil, domain.NewError(domain.ErrInvalidContract, "configure network route", "network route type is unsupported")
	}
	return transport, nil
}

func parseProxyEndpoint(raw string, schemes ...string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, domain.NewError(domain.ErrInvalidContract, "configure network route", "proxy endpoint must be an origin without embedded credentials")
	}
	for _, scheme := range schemes {
		if strings.EqualFold(endpoint.Scheme, scheme) {
			return endpoint, nil
		}
	}
	return nil, domain.NewError(domain.ErrInvalidContract, "configure network route", fmt.Sprintf("proxy endpoint scheme must be one of %s", strings.Join(schemes, ", ")))
}

type socks5Dialer struct {
	address string
	dialer  *net.Dialer
}

func (d socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, domain.NewError(domain.ErrInvalidContract, "dial SOCKS5", "only TCP is supported")
	}
	connection, err := d.dialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := negotiateSOCKS5(connection, address); err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}
