package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/pipeline"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/security"
	"github.com/agentveil/agentveil/internal/session"
	veilstream "github.com/agentveil/agentveil/internal/stream"
)

const (
	HeaderSession    = "X-Veil-Session"
	HeaderRouteToken = "X-Veil-Route-Token"
)

type Route struct {
	ID                                string
	Upstream                          *url.URL
	Policy                            policy.Engine
	MaxRequestBytes, MaxResponseBytes int64
	VaultLimits                       redactor.Limits
	Interactive                       bool
	Approver                          interface {
		Request(context.Context, domain.Finding) (domain.Action, error)
	}
}
type configuredRoute struct {
	Route
	allowlist *security.UpstreamAllowlist
}
type Handler struct {
	sessions *session.Manager
	routes   map[string]configuredRoute
	client   *http.Client
	scanner  *detector.Scanner
}

func NewHandler(sessions *session.Manager, routes []Route, client *http.Client) (*Handler, error) {
	if sessions == nil || client == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "session manager and HTTP client are required")
	}
	h := &Handler{sessions: sessions, routes: make(map[string]configuredRoute, len(routes)), client: client, scanner: detector.NewDefault()}
	for _, route := range routes {
		if route.ID == "" || route.Upstream == nil || route.MaxRequestBytes <= 0 || route.MaxResponseBytes <= 0 {
			return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "route is incomplete")
		}
		port := uint16(443)
		if route.Upstream.Scheme == "http" {
			port = 80
		}
		if value := route.Upstream.Port(); value != "" {
			parsed, err := strconv.ParseUint(value, 10, 16)
			if err != nil || parsed == 0 {
				return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "upstream port is invalid")
			}
			port = uint16(parsed)
		}
		allowlist, err := security.NewUpstreamAllowlist([]domain.Upstream{{Scheme: route.Upstream.Scheme, Host: route.Upstream.Hostname(), Port: port}})
		if err != nil {
			return nil, err
		}
		if err := allowlist.ValidateURL(route.Upstream); err != nil {
			return nil, err
		}
		if _, exists := h.routes[route.ID]; exists {
			return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "duplicate route id")
		}
		h.routes[route.ID] = configuredRoute{Route: route, allowlist: allowlist}
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	routeID, endpoint, ok := splitRoutePath(r.URL.Path)
	if !ok {
		fail(w, http.StatusNotFound, "UNKNOWN_ROUTE")
		return
	}
	route, ok := h.routes[routeID]
	if !ok {
		fail(w, http.StatusNotFound, "UNKNOWN_ROUTE")
		return
	}
	secret, ok := h.sessions.AuthorizeAndSecret(r.Header.Get(HeaderSession), routeID, r.Header.Get(HeaderRouteToken))
	if !ok {
		fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
		return
	}
	body, err := readLimited(r.Body, route.MaxRequestBytes)
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		return
	}
	vault, err := redactor.NewVault(secret, route.VaultLimits)
	for i := range secret {
		secret[i] = 0
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "VAULT_FAILURE")
		return
	}
	defer vault.Destroy()
	processed, err := pipeline.Process(pipeline.Context{SurfaceID: routeID, Interactive: route.Interactive, RequestContext: r.Context(), Approver: route.Approver}, endpoint, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body, h.scanner, route.Policy, vault)
	if err != nil {
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	target := *route.Upstream
	target.Path = strings.TrimSuffix(route.Upstream.Path, "/") + endpoint
	target.RawQuery = r.URL.RawQuery
	upstreamRequest, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(processed.Body))
	if err != nil {
		fail(w, http.StatusBadGateway, "UPSTREAM_REQUEST_FAILED")
		return
	}
	copyHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.Header.Del(HeaderSession)
	upstreamRequest.Header.Del(HeaderRouteToken)
	upstreamRequest.Header.Del("Content-Encoding")
	upstreamRequest.ContentLength = int64(len(processed.Body))
	client := *h.client
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error { return route.allowlist.ValidateURL(request.URL) }
	response, err := client.Do(upstreamRequest)
	if err != nil {
		fail(w, http.StatusBadGateway, "UPSTREAM_FAILURE")
		return
	}
	defer response.Body.Close()
	if strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		h.streamResponse(w, response, vault, route.MaxResponseBytes)
		return
	}
	responseBody, err := readLimited(response.Body, route.MaxResponseBytes)
	if err != nil {
		fail(w, http.StatusBadGateway, "RESPONSE_TOO_LARGE")
		return
	}
	restored, err := pipeline.ProcessResponse(processed.Protocol, response.Header.Get("Content-Type"), responseBody, h.scanner, vault)
	if err != nil {
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Content-Length")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(restored)
}

func (h *Handler) streamResponse(w http.ResponseWriter, response *http.Response, vault *redactor.Vault, maxBytes int64) {
	guard, err := veilstream.NewGuard(h.scanner, vault, 256, int(maxBytes))
	if err != nil {
		fail(w, http.StatusInternalServerError, errorCode(err))
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Content-Length")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	flusher, _ := w.(http.Flusher)
	buffer := make([]byte, 4096)
	var total int64
	for {
		count, readErr := response.Body.Read(buffer)
		total += int64(count)
		if total > maxBytes {
			return
		}
		if count > 0 {
			safe, guardErr := guard.Push(string(buffer[:count]))
			if guardErr != nil {
				return
			}
			if safe != "" {
				_, _ = io.WriteString(w, safe)
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		if readErr == io.EOF {
			tail, guardErr := guard.Close()
			if guardErr == nil {
				_, _ = io.WriteString(w, tail)
				if flusher != nil {
					flusher.Flush()
				}
			}
			return
		}
		if readErr != nil {
			return
		}
	}
}

func splitRoutePath(path string) (string, string, bool) {
	rest := strings.TrimPrefix(path, "/route/")
	if rest == path {
		return "", "", false
	}
	id, suffix, found := strings.Cut(rest, "/")
	if !found || id == "" {
		return "", "", false
	}
	return id, "/" + suffix, true
}
func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, domain.NewError(domain.ErrInvalidContract, "read body", "body limit exceeded")
	}
	return value, nil
}
func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		if !isHopHeader(key) {
			destination[key] = append([]string(nil), values...)
		}
	}
}
func isHopHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}
func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`)
}
func errorCode(err error) string {
	if veil, ok := err.(*domain.VeilError); ok {
		return string(veil.Code)
	}
	return "INTERNAL_ERROR"
}
