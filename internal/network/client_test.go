package network

import (
	"net/http"
	"net/url"
	"testing"

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
