package security

import (
	"net/url"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func FuzzUpstreamAllowlistRejectsOriginConfusion(f *testing.F) {
	allowlist, err := NewUpstreamAllowlist([]domain.Upstream{{Scheme: "https", Host: "api.example.com", Port: 443}})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"https://api.example.com/v1/responses",
		"https://api.example.com.:443/v1",
		"https://api.example.com@evil.example/v1",
		"https://evil.example@api.example.com/v1",
		"https://api.example.com:443@evil.example/v1",
		"http://api.example.com:443/v1",
		"https://api.example.com:444/v1",
		"https://api.example.com/v1#https://evil.example",
		"https:%2f%2fevil.example@api.example.com/v1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		target, parseErr := url.Parse(raw)
		validationErr := allowlist.ValidateURL(target)
		if validationErr != nil {
			return
		}
		if parseErr != nil || target == nil || target.User != nil || target.Fragment != "" || !strings.EqualFold(target.Scheme, "https") || strings.TrimSuffix(strings.ToLower(target.Hostname()), ".") != "api.example.com" {
			t.Fatal("allowlist accepted an origin-confused URL")
		}
		port, err := effectivePort(target)
		if err != nil || port != 443 {
			t.Fatal("allowlist accepted a non-HTTPS default port")
		}
	})
}
