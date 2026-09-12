package security

import (
	"net/url"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestAllowlistRequiresExactOriginAndRechecksRedirect(t *testing.T) {
	allowlist, err := NewUpstreamAllowlist([]domain.Upstream{{Scheme: "https", Host: "api.example.com", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := url.Parse("https://api.example.com/v1/responses")
	if err := allowlist.ValidateURL(allowed); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://api.example.com/v1", "https://evil.example/v1", "https://api.example.com:444/v1", "https://user:pass@api.example.com/v1"} {
		target, _ := url.Parse(raw)
		if err := allowlist.CheckRedirect(allowed, target); err == nil {
			t.Fatalf("disallowed target accepted: %s", raw)
		}
	}
}

func TestAllowlistRejectsUnboundedOriginSets(t *testing.T) {
	if _, err := NewUpstreamAllowlist(nil); err == nil {
		t.Fatal("empty upstream allowlist accepted")
	}
	upstreams := make([]domain.Upstream, MaxAllowedUpstreams+1)
	for index := range upstreams {
		upstreams[index] = domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}
	}
	if _, err := NewUpstreamAllowlist(upstreams); err == nil {
		t.Fatal("unbounded upstream allowlist accepted")
	}
}
