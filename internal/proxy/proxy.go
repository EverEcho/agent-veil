package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	veilnetwork "github.com/agentveil/agentveil/internal/network"
	"github.com/agentveil/agentveil/internal/pipeline"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/security"
	"github.com/agentveil/agentveil/internal/session"
)

const (
	HeaderSession       = "X-Veil-Session"
	HeaderRouteToken    = "X-Veil-Route-Token"
	CapabilityPrefix    = "veil-v1:"
	defaultChunkBytes   = detector.DefaultChunkBytes
	defaultOverlapBytes = detector.DefaultOverlapBytes
	MaxProxyRoutes      = 256
	MaxProxyBodyBytes   = 64 << 20
)

var routeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Route struct {
	ID                                          string
	AgentID, SurfaceID, Workspace, WorkspaceRef string
	Protocol                                    domain.Protocol
	Upstream                                    *url.URL
	Policy                                      policy.Engine
	MaxRequestBytes, MaxResponseBytes           int64
	VaultLimits                                 redactor.Limits
	Interactive                                 bool
	Approver                                    interface {
		Request(context.Context, domain.Finding) (domain.Action, error)
	}
	Auth        domain.AuthStrategy
	AuthApplier veilauth.Applier
	Network     domain.NetworkRoute
	Auditor     interface {
		Append(domain.AuditEvent) error
	}
	CapabilityHeader string
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
	scanner  detector.ContentScanner
}

func NewHandler(sessions *session.Manager, routes []Route, client *http.Client) (*Handler, error) {
	scanner, err := detector.NewDefaultChunked()
	if err != nil {
		return nil, err
	}
	return NewHandlerWithScanner(sessions, routes, client, scanner)
}

func NewHandlerWithScanner(sessions *session.Manager, routes []Route, client *http.Client, scanner detector.ContentScanner) (*Handler, error) {
	if sessions == nil || client == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "session manager and HTTP client are required")
	}
	if scanner == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "content scanner is required")
	}
	if len(routes) == 0 || len(routes) > MaxProxyRoutes {
		return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "route count must be within its configured bounds")
	}
	h := &Handler{sessions: sessions, routes: make(map[string]configuredRoute, len(routes)), client: client, scanner: scanner}
	for _, route := range routes {
		if !routeIDPattern.MatchString(route.ID) || route.Upstream == nil || route.MaxRequestBytes <= 0 || route.MaxRequestBytes > MaxProxyBodyBytes || route.MaxResponseBytes <= 0 || route.MaxResponseBytes > MaxProxyBodyBytes {
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
	secureResponseHeaders(w.Header())
	if !security.ValidLocalOrigin(r) {
		fail(w, http.StatusForbidden, string(domain.ErrInvalidOrigin))
		return
	}
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
	sessionValues, routeTokenValues := r.Header.Values(HeaderSession), r.Header.Values(HeaderRouteToken)
	var sessionID, routeToken string
	if route.CapabilityHeader != "" {
		encodedValues := r.Header.Values(route.CapabilityHeader)
		r.Header.Del(route.CapabilityHeader)
		if len(encodedValues) != 1 || len(sessionValues) != 0 || len(routeTokenValues) != 0 {
			fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
			return
		}
		if decodedSession, decodedToken, valid := DecodeCapability(encodedValues[0]); valid {
			sessionID, routeToken = decodedSession, decodedToken
		} else {
			fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
			return
		}
	} else if len(sessionValues) != 1 || len(routeTokenValues) != 1 {
		fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
		return
	} else {
		sessionID, routeToken = sessionValues[0], routeTokenValues[0]
	}
	authorization, ok := h.sessions.AuthorizeRoute(sessionID, routeID, routeToken)
	if !ok {
		fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
		return
	}
	requestContext, cancel := context.WithDeadline(r.Context(), authorization.ExpiresAt)
	stopRevocation := context.AfterFunc(authorization.Context, cancel)
	defer func() {
		stopRevocation()
		cancel()
	}()
	started := time.Now()
	auditEvent := domain.AuditEvent{SessionID: sessionID, AgentID: route.AgentID, SurfaceID: route.SurfaceID, Protocol: route.Protocol, Action: domain.ActionAllow, WorkspaceRef: route.WorkspaceRef}
	defer func() {
		if route.Auditor == nil {
			return
		}
		auditEvent.Timestamp = time.Now().UTC()
		auditEvent.LatencyMS = time.Since(started).Milliseconds()
		_ = route.Auditor.Append(auditEvent)
	}()
	if !routeAllowsMethod(route.Protocol, r.Method) {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnsupportedMethod
		w.Header().Set("Allow", allowedMethods(route.Protocol))
		fail(w, http.StatusMethodNotAllowed, string(domain.ErrUnsupportedMethod))
		return
	}
	if _, err := protocol.ResolveEndpoint(route.Protocol, endpoint); err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusForbidden, string(domain.ErrUnknownProtocol))
		return
	}
	mcpVersion := ""
	if route.Protocol == domain.ProtocolMCPStreamable {
		var err error
		if mcpVersion, err = protocol.ResolveMCPStreamableVersion(r.Header.Values(protocol.HeaderMCPProtocolVersion)); err != nil {
			auditEvent.Action = domain.ActionBlock
			auditEvent.ErrorCode = domain.ErrUnknownProtocol
			fail(w, http.StatusBadRequest, string(domain.ErrUnknownProtocol))
			return
		}
		if err := protocol.ValidateMCPStreamableAccept(r.Method, r.Header.Values("Accept")); err != nil {
			auditEvent.Action = domain.ActionBlock
			auditEvent.ErrorCode = domain.ErrUnknownProtocol
			fail(w, http.StatusBadRequest, string(domain.ErrUnknownProtocol))
			return
		}
	}
	if _, ok := uniqueHeaderValue(r.Header, "Content-Type"); !ok {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusForbidden, string(domain.ErrUnknownProtocol))
		return
	}
	if _, ok := uniqueHeaderValue(r.Header, "Content-Encoding"); !ok {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnsupportedEncoding
		fail(w, http.StatusForbidden, string(domain.ErrUnsupportedEncoding))
		return
	}
	body, err := readLimited(r.Body, route.MaxRequestBytes)
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = "REQUEST_TOO_LARGE"
		fail(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		return
	}
	vault, err := redactor.NewVault(authorization.Secret, route.VaultLimits)
	for i := range authorization.Secret {
		authorization.Secret[i] = 0
	}
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = "VAULT_FAILURE"
		fail(w, http.StatusInternalServerError, "VAULT_FAILURE")
		return
	}
	defer vault.Destroy()
	surfaceID := route.SurfaceID
	if surfaceID == "" {
		surfaceID = routeID
	}
	processed := pipeline.Result{Body: body, Protocol: route.Protocol, Vault: vault}
	mcpVersionMismatch := false
	if r.Method != http.MethodPost {
		if len(body) != 0 {
			auditEvent.Action = domain.ActionBlock
			auditEvent.ErrorCode = domain.ErrUnknownProtocol
			fail(w, http.StatusForbidden, string(domain.ErrUnknownProtocol))
			return
		}
	} else {
		processed, err = pipeline.ProcessForProtocol(pipeline.Context{AgentID: route.AgentID, Workspace: route.Workspace, Provider: route.Upstream.Hostname(), SurfaceID: surfaceID, Interactive: route.Interactive, RequestContext: requestContext, Approver: route.Approver}, route.Protocol, endpoint, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body, h.scanner, route.Policy, vault)
		if err == nil && route.Protocol == domain.ProtocolMCPStreamable {
			err = protocol.ValidateMCPStreamableBodyVersion(mcpVersion, processed.Body)
			mcpVersionMismatch = err != nil
		}
	}
	applyAuditResult(&auditEvent, processed)
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = errorCodeValue(err)
		status := http.StatusForbidden
		if mcpVersionMismatch {
			status = http.StatusBadRequest
		}
		fail(w, status, errorCode(err))
		return
	}
	target := *route.Upstream
	target.Path = joinBasePath(route.Upstream.Path, endpoint)
	target.RawQuery = r.URL.RawQuery
	upstreamRequest, err := http.NewRequestWithContext(requestContext, r.Method, target.String(), bytes.NewReader(processed.Body))
	if err != nil {
		auditEvent.ErrorCode = "UPSTREAM_REQUEST_FAILED"
		fail(w, http.StatusBadGateway, "UPSTREAM_REQUEST_FAILED")
		return
	}
	copyHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.Header.Del(HeaderSession)
	upstreamRequest.Header.Del(HeaderRouteToken)
	upstreamRequest.Header.Del("Content-Encoding")
	upstreamRequest.Header.Set("Accept-Encoding", "identity")
	upstreamRequest.ContentLength = int64(len(processed.Body))
	authStrategy := route.Auth
	if authStrategy.Type == "" {
		authStrategy.Type = domain.AuthPassthrough
	}
	if err := route.AuthApplier.Apply(upstreamRequest, authStrategy); err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	client := *route.client
	if route.Protocol == domain.ProtocolMCPStreamable && r.Method == http.MethodGet {
		client.Timeout = 0
	}
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error { return route.allowlist.ValidateURL(request.URL) }
	response, err := client.Do(upstreamRequest)
	if err != nil {
		auditEvent.ErrorCode = "UPSTREAM_FAILURE"
		fail(w, http.StatusBadGateway, "UPSTREAM_FAILURE")
		return
	}
	defer response.Body.Close()
	responseEncoding, uniqueEncoding := uniqueHeaderValue(response.Header, "Content-Encoding")
	if !uniqueEncoding || strings.TrimSpace(responseEncoding) != "" && !strings.EqualFold(responseEncoding, "identity") {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnsupportedEncoding
		fail(w, http.StatusBadGateway, string(domain.ErrUnsupportedEncoding))
		return
	}
	responseContentType, uniqueContentType := uniqueHeaderValue(response.Header, "Content-Type")
	if !uniqueContentType {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusBadGateway, string(domain.ErrUnknownProtocol))
		return
	}
	if protocol.MediaTypeIs(responseContentType, "text/event-stream") {
		if err := h.streamResponse(w, response, vault, route.MaxResponseBytes, processed.Protocol); err != nil {
			auditEvent.Action = domain.ActionBlock
			auditEvent.ErrorCode = errorCodeValue(err)
		}
		return
	}
	responseBody, err := readLimited(response.Body, route.MaxResponseBytes)
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = "RESPONSE_TOO_LARGE"
		fail(w, http.StatusBadGateway, "RESPONSE_TOO_LARGE")
		return
	}
	if len(responseBody) == 0 {
		copyHeaders(w.Header(), response.Header)
		w.Header().Del("Content-Length")
		secureResponseHeaders(w.Header())
		w.WriteHeader(response.StatusCode)
		return
	}
	restored, err := pipeline.ProcessResponse(processed.Protocol, responseContentType, responseBody, h.scanner, vault)
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusForbidden, errorCode(err))
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Content-Length")
	secureResponseHeaders(w.Header())
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(restored)
}

func joinBasePath(basePath, endpoint string) string {
	base := strings.FieldsFunc(basePath, func(character rune) bool { return character == '/' })
	suffix := strings.FieldsFunc(endpoint, func(character rune) bool { return character == '/' })
	overlap := 0
	maximum := len(base)
	if len(suffix) < maximum {
		maximum = len(suffix)
	}
	for candidate := maximum; candidate > 0; candidate-- {
		equal := true
		for index := 0; index < candidate; index++ {
			if base[len(base)-candidate+index] != suffix[index] {
				equal = false
				break
			}
		}
		if equal {
			overlap = candidate
			break
		}
	}
	parts := append(append([]string(nil), base...), suffix[overlap:]...)
	return "/" + strings.Join(parts, "/")
}

func (h *Handler) streamResponse(w http.ResponseWriter, response *http.Response, vault *redactor.Vault, maxBytes int64, protocolType domain.Protocol) error {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		fail(w, http.StatusInternalServerError, "STREAM_DEADLINE_FAILURE")
		return domain.NewError(domain.ErrInvalidContract, "stream response", "cannot clear streaming write deadline")
	}
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
			secureResponseHeaders(w.Header())
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
		secureResponseHeaders(w.Header())
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

func routeAllowsMethod(protocolType domain.Protocol, method string) bool {
	return method == http.MethodPost || protocolType == domain.ProtocolMCPStreamable && (method == http.MethodGet || method == http.MethodDelete)
}

func allowedMethods(protocolType domain.Protocol) string {
	if protocolType == domain.ProtocolMCPStreamable {
		return http.MethodDelete + ", " + http.MethodGet + ", " + http.MethodPost
	}
	return http.MethodPost
}

func EncodeCapability(sessionID, routeToken string) string {
	return CapabilityPrefix + sessionID + ":" + routeToken
}

func DecodeCapability(value string) (string, string, bool) {
	if !strings.HasPrefix(value, CapabilityPrefix) {
		return "", "", false
	}
	value = strings.TrimPrefix(value, CapabilityPrefix)
	if value == "" {
		return "", "", false
	}
	sessionID, routeToken, found := strings.Cut(value, ":")
	if !found || sessionID == "" || routeToken == "" || strings.Contains(routeToken, ":") {
		return "", "", false
	}
	return sessionID, routeToken, true
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
	dynamicHopHeaders := make(map[string]struct{})
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				dynamicHopHeaders[name] = struct{}{}
			}
		}
	}
	for key, values := range source {
		_, dynamicallyHopByHop := dynamicHopHeaders[http.CanonicalHeaderKey(key)]
		if !isHopHeader(key) && !dynamicallyHopByHop {
			destination[key] = append([]string(nil), values...)
		}
	}
}

func uniqueHeaderValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) > 1 {
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	return values[0], true
}

func isHopHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}
func fail(w http.ResponseWriter, status int, code string) {
	secureResponseHeaders(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`)
}

func secureResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
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
