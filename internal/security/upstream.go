package security

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type UpstreamAllowlist struct {
	allowed map[string]struct{}
}

func NewUpstreamAllowlist(upstreams []domain.Upstream) (*UpstreamAllowlist, error) {
	a := &UpstreamAllowlist{allowed: make(map[string]struct{}, len(upstreams))}
	for _, upstream := range upstreams {
		if err := upstream.Validate(); err != nil {
			return nil, err
		}
		a.allowed[key(upstream.Scheme, upstream.Host, upstream.Port)] = struct{}{}
	}
	return a, nil
}

func (a *UpstreamAllowlist) ValidateURL(target *url.URL) error {
	if target == nil || target.User != nil || target.Fragment != "" || target.Hostname() == "" {
		return domain.NewError(domain.ErrUpstreamDenied, "validate target", "target URL is malformed")
	}
	port, err := effectivePort(target)
	if err != nil {
		return domain.NewError(domain.ErrUpstreamDenied, "validate target", "target port is invalid")
	}
	if _, ok := a.allowed[key(target.Scheme, target.Hostname(), port)]; !ok {
		return domain.NewError(domain.ErrUpstreamDenied, "validate target", "target is not in the protection plan")
	}
	return nil
}

func (a *UpstreamAllowlist) CheckRedirect(_ *url.URL, target *url.URL) error {
	return a.ValidateURL(target)
}

func effectivePort(target *url.URL) (uint16, error) {
	if value := target.Port(); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 16)
		return uint16(parsed), err
	}
	switch strings.ToLower(target.Scheme) {
	case "https":
		return 443, nil
	case "http":
		return 80, nil
	default:
		return 0, domain.NewError(domain.ErrUpstreamDenied, "validate target", "unsupported scheme")
	}
}

func key(scheme, host string, port uint16) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		host = ip.String()
	}
	return strings.ToLower(scheme) + "://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
}
