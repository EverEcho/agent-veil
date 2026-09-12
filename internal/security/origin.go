package security

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func ValidLoopbackAuthority(authority string) bool {
	parsed, err := url.Parse("http://" + authority)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func ValidLocalOrigin(request *http.Request) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return false
	}
	origin, err := url.Parse(value)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || !ValidLoopbackAuthority(origin.Host) {
		return false
	}
	expectedScheme := "http"
	if request.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(origin.Scheme, expectedScheme) && strings.EqualFold(origin.Host, request.Host)
}
