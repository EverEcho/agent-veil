package network

import (
	"net/http"
	"time"

	"github.com/agentveil/agentveil/internal/security"
)

func NewHTTPClient(transport http.RoundTripper, allowlist *security.UpstreamAllowlist) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(request *http.Request, _ []*http.Request) error { return allowlist.ValidateURL(request.URL) }}
}
