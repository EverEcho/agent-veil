package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	veilnetwork "github.com/agentveil/agentveil/internal/network"
	"github.com/agentveil/agentveil/internal/pipeline"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/security"
	"github.com/agentveil/agentveil/internal/session"
)

const (
	HeaderSession    = "X-Veil-Session"
	HeaderRouteToken = "X-Veil-Route-Token"
)

type Route struct {
	ID                                string
	AgentID, SurfaceID, WorkspaceRef  string
	Protocol                          domain.Protocol
	Upstream                          *url.URL
	Policy                            policy.Engine
	MaxRequestBytes, MaxResponseBytes int64
	VaultLimits                       redactor.Limits
	Interactive                       bool
	Approver                          interface {
		Request(context.Context, domain.Finding) (domain.Action, error)
	}
	Auth        domain.AuthStrategy
	AuthApplier veilauth.Applier
	Network     domain.NetworkRoute
	Auditor     interface {
		Append(domain.AuditEvent) error
	}
}
type configuredRoute struct {
	Route
	allowlist *security.UpstreamAllowlist
	client    *http.Client
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
		routeClient := *client
		if route.Network.Type != "" {
			transport, err := veilnetwork.NewTransport(route.Network)
			if err != nil {
				return nil, err
			}
			routeClient.Transport = transport
		}
		h.routes[route.ID] = configuredRoute{Route: route, allowlist: allowlist, client: &routeClient}
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
	started := time.Now()
	auditEvent := domain.AuditEvent{SessionID: r.Header.Get(HeaderSession), AgentID: route.AgentID, SurfaceID: route.SurfaceID, Protocol: route.Protocol, Action: domain.ActionAllow, WorkspaceRef: route.WorkspaceRef}
	defer func() {
		if route.Auditor == nil {
			return
		}
		auditEvent.Timestamp = time.Now().UTC()
		auditEvent.LatencyMS = time.Since(started).Milliseconds()
		_ = route.Auditor.Append(auditEvent)
	}()
	body, err := readLimited(r.Body, route.MaxRequestBytes)
	if err != nil {
		auditEvent.ErrorCode = "REQUEST_TOO_LARGE"
		fail(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		return
	}
	vault, err := redactor.NewVault(secret, route.VaultLimits)
	for i := range secret {
		secret[i] = 0
	}
	if err != nil {
		auditEvent.ErrorCode = "VAULT_FAILURE"
		fail(w, http.StatusInternalServerError, "VAULT_FAILURE")
		return
	}
	defer vault.Destroy()
	processed, err := pipeline.Process(pipeline.Context{SurfaceID: routeID, Interactive: route.Interactive, RequestContext: r.Context(), Approver: route.Approver}, endpoint, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body, h.scanner, route.Policy, vault)
	applyAuditResult(&auditEvent, processed)
	if err != nil {
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	target := *route.Upstream
	target.Path = strings.TrimSuffix(route.Upstream.Path, "/") + endpoint
	target.RawQuery = r.URL.RawQuery
	upstreamRequest, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(processed.Body))
	if err != nil {
		auditEvent.ErrorCode = "UPSTREAM_REQUEST_FAILED"
		fail(w, http.StatusBadGateway, "UPSTREAM_REQUEST_FAILED")
		return
	}
	copyHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.Header.Del(HeaderSession)
	upstreamRequest.Header.Del(HeaderRouteToken)
	upstreamRequest.Header.Del("Content-Encoding")
	upstreamRequest.ContentLength = int64(len(processed.Body))
	authStrategy := route.Auth
	if authStrategy.Type == "" {
		authStrategy.Type = domain.AuthPassthrough
	}
	if err := route.AuthApplier.Apply(upstreamRequest, authStrategy); err != nil {
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	client := *route.client
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error { return route.allowlist.ValidateURL(request.URL) }
	response, err := client.Do(upstreamRequest)
	if err != nil {
		auditEvent.ErrorCode = "UPSTREAM_FAILURE"
		fail(w, http.StatusBadGateway, "UPSTREAM_FAILURE")
		return
	}
	defer response.Body.Close()
	if strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		if err := h.streamResponse(w, response, vault, route.MaxResponseBytes, processed.Protocol); err != nil {
			auditEvent.ErrorCode = errorCodeValue(err)
		}
		return
	}
	responseBody, err := readLimited(response.Body, route.MaxResponseBytes)
	if err != nil {
		auditEvent.ErrorCode = "RESPONSE_TOO_LARGE"
		fail(w, http.StatusBadGateway, "RESPONSE_TOO_LARGE")
		return
	}
	restored, err := pipeline.ProcessResponse(processed.Protocol, response.Header.Get("Content-Type"), responseBody, h.scanner, vault)
	if err != nil {
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Content-Length")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(restored)
}

func (h *Handler) streamResponse(w http.ResponseWriter, response *http.Response, vault *redactor.Vault, maxBytes int64, protocolType domain.Protocol) error {
	maxEventBytes := int64(1 << 20)
	if maxBytes < maxEventBytes {
		maxEventBytes = maxBytes
	}
	processor, err := pipeline.NewSSEProcessor(protocolType, h.scanner, vault, int(maxEventBytes), 512)
	if err != nil {
		fail(w, http.StatusForbidden, errorCode(err))
		return err
	}
	wroteHeader := false
	writeChunk := func(chunk []byte) error {
		if len(chunk) == 0 {
			return nil
		}
		if !wroteHeader {
			copyHeaders(w.Header(), response.Header)
			w.Header().Del("Content-Length")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(response.StatusCode)
			wroteHeader = true
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return nil
	}
	failBeforeWrite := func(status int, code string) {
		if !wroteHeader {
			fail(w, status, code)
		}
	}
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > maxBytes {
				err := domain.NewError(domain.ErrInvalidContract, "read stream", "response body limit exceeded")
				failBeforeWrite(http.StatusBadGateway, "RESPONSE_TOO_LARGE")
				return err
			}
			processed, processErr := processor.Push(buffer[:read])
			if processErr != nil {
				failBeforeWrite(http.StatusForbidden, errorCode(processErr))
				return processErr
			}
			if err := writeChunk(processed); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			failBeforeWrite(http.StatusBadGateway, "UPSTREAM_FAILURE")
			return readErr
		}
	}
	tail, err := processor.Close()
	if err != nil {
		failBeforeWrite(http.StatusForbidden, errorCode(err))
		return err
	}
	if err := writeChunk(tail); err != nil {
		return err
	}
	if !wroteHeader {
		copyHeaders(w.Header(), response.Header)
		w.Header().Del("Content-Length")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(response.StatusCode)
	}
	return nil
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

func errorCodeValue(err error) domain.ErrorCode { return domain.ErrorCode(errorCode(err)) }

func applyAuditResult(event *domain.AuditEvent, result pipeline.Result) {
	if result.Protocol != "" {
		event.Protocol = result.Protocol
	}
	event.FindingCount = len(result.Findings)
	seen := map[string]struct{}{}
	for _, finding := range result.Findings {
		if _, ok := seen[finding.Category]; !ok {
			event.FindingTypes = append(event.FindingTypes, finding.Category)
			seen[finding.Category] = struct{}{}
		}
		if severityRank(finding.Severity) > severityRank(event.Severity) {
			event.Severity = finding.Severity
		}
	}
	for _, action := range result.Actions {
		if actionRank(action) > actionRank(event.Action) {
			event.Action = action
		}
	}
}

func severityRank(value domain.Severity) int {
	return map[domain.Severity]int{domain.SeverityLow: 1, domain.SeverityMedium: 2, domain.SeverityHigh: 3, domain.SeverityCritical: 4}[value]
}

func actionRank(value domain.Action) int {
	return map[domain.Action]int{domain.ActionAllow: 1, domain.ActionAsk: 2, domain.ActionRedact: 3, domain.ActionBlock: 4}[value]
}
