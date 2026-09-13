package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
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
	HeaderSession          = "X-Veil-Session"
	HeaderRouteToken       = "X-Veil-Route-Token"
	CapabilityPrefix       = "veil-v1:"
	defaultChunkBytes      = detector.DefaultChunkBytes
	defaultOverlapBytes    = detector.DefaultOverlapBytes
	MaxProxyRoutes         = 256
	MaxProxyBodyBytes      = 64 << 20
	maxResponseHeaders     = 256
	maxResponseHeaderBytes = 64 << 10
	maxRequestHeaders      = 256
	maxRequestHeaderBytes  = 64 << 10
	maxRequestQueryValues  = 256
	maxRequestQueryBytes   = 64 << 10
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
	CapabilityPath   bool
	LegacySessions   *LegacySSEManager
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
		if route.Protocol == domain.ProtocolMCPLegacySSE && route.LegacySessions == nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "create proxy", "legacy SSE route requires a shared channel manager")
		}
		routeClient := *client
		// Provider cookies are an implicit cross-request credential channel. A
		// caller-supplied Jar would persist response headers before DLP can inspect
		// them and replay that state on later protected requests.
		routeClient.Jar = nil
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
	if encoded, strippedEndpoint, pathCapability := splitCapabilityPath(endpoint); route.CapabilityPath && pathCapability {
		if decodedSession, decodedToken, valid := DecodeCapability(encoded); valid {
			redundantLegacyHeaders := route.Protocol == domain.ProtocolMCPLegacySSE && len(sessionValues) == 1 && len(routeTokenValues) == 1 && sessionValues[0] == decodedSession && routeTokenValues[0] == decodedToken
			if len(sessionValues) != 0 || len(routeTokenValues) != 0 {
				if !redundantLegacyHeaders {
					fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
					return
				}
			}
			sessionID, routeToken, endpoint = decodedSession, decodedToken, strippedEndpoint
		} else {
			fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
			return
		}
	} else if route.CapabilityHeader != "" {
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
	interactive := route.Interactive && authorization.Interactive
	requestContext, cancel := context.WithDeadline(r.Context(), authorization.ExpiresAt)
	stopRevocation := context.AfterFunc(authorization.Context, cancel)
	defer func() {
		stopRevocation()
		cancel()
	}()
	stopBodyRead := context.AfterFunc(requestContext, func() { _ = r.Body.Close() })
	defer stopBodyRead()
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
	if route.Protocol == domain.ProtocolMCPLegacySSE {
		h.serveLegacySSE(w, r, route, routeID, endpoint, sessionID, routeToken, authorization, interactive, &auditEvent)
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
	if requestsProtocolUpgrade(r.Header) {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusForbidden, string(domain.ErrUnknownProtocol))
		return
	}
	if len(r.Header.Values("Cookie")) != 0 {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusForbidden, string(domain.ErrUnknownProtocol))
		return
	}
	if err := validateRequestHeaderBounds(r.Header); err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrInvalidContract
		fail(w, http.StatusRequestHeaderFieldsTooLarge, string(domain.ErrInvalidContract))
		return
	}
	if err := validateRequestQuery(r.URL.RawQuery); err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrInvalidContract
		fail(w, http.StatusBadRequest, string(domain.ErrInvalidContract))
		return
	}
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
		if requestContext.Err() != nil {
			auditEvent.ErrorCode = domain.ErrUnauthorizedRoute
			fail(w, http.StatusUnauthorized, string(domain.ErrUnauthorizedRoute))
		} else {
			auditEvent.ErrorCode = "REQUEST_TOO_LARGE"
			fail(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		}
		return
	}
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
		processed, err = pipeline.ProcessForProtocol(pipeline.Context{AgentID: route.AgentID, Workspace: route.Workspace, Provider: route.Upstream.Hostname(), SurfaceID: surfaceID, Interactive: interactive, RequestContext: requestContext, Approver: route.Approver}, route.Protocol, endpoint, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body, h.scanner, route.Policy, vault)
		if err == nil && route.Protocol == domain.ProtocolMCPStreamable {
			err = protocol.ValidateMCPStreamableBodyVersion(mcpVersion, processed.Body)
			mcpVersionMismatch = err != nil
		}
	}
	if err != nil {
		applyAuditResult(&auditEvent, processed)
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
	target.Path = protectedTargetPath(route.Protocol, route.Upstream.Path, endpoint)
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
	headerResult, err := processRequestHeaders(pipeline.Context{AgentID: route.AgentID, Workspace: route.Workspace, Provider: route.Upstream.Hostname(), SurfaceID: surfaceID, Interactive: interactive, RequestContext: requestContext, Approver: route.Approver}, upstreamRequest.Header, h.scanner, route.Policy, vault)
	processed.Findings = append(processed.Findings, headerResult.Findings...)
	processed.Actions = append(processed.Actions, headerResult.Actions...)
	if err == nil {
		var queryResult pipeline.TextResult
		queryResult, err = processRequestQuery(pipeline.Context{AgentID: route.AgentID, Workspace: route.Workspace, Provider: route.Upstream.Hostname(), SurfaceID: surfaceID, Interactive: interactive, RequestContext: requestContext, Approver: route.Approver}, upstreamRequest.URL, h.scanner, route.Policy, vault)
		processed.Findings = append(processed.Findings, queryResult.Findings...)
		processed.Actions = append(processed.Actions, queryResult.Actions...)
	}
	applyAuditResult(&auditEvent, processed)
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusForbidden, errorCode(err))
		return
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
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
		if err := route.allowlist.ValidateURL(request.URL); err != nil {
			return err
		}
		if request.Method != upstreamRequest.Method || request.URL.EscapedPath() != upstreamRequest.URL.EscapedPath() || request.URL.RawQuery != upstreamRequest.URL.RawQuery {
			return domain.NewError(domain.ErrUpstreamDenied, "validate redirect", "redirect changed the protected endpoint")
		}
		return nil
	}
	response, err := client.Do(upstreamRequest)
	if err != nil {
		auditEvent.ErrorCode = "UPSTREAM_FAILURE"
		fail(w, http.StatusBadGateway, "UPSTREAM_FAILURE")
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusBadGateway, string(domain.ErrUnknownProtocol))
		return
	}
	if len(response.Header.Values("Set-Cookie")) != 0 {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = domain.ErrUnknownProtocol
		fail(w, http.StatusBadGateway, string(domain.ErrUnknownProtocol))
		return
	}
	responseHeaderResult, err := processResponseHeaders(response.Header, h.scanner, vault)
	processed.Findings = append(processed.Findings, responseHeaderResult.Findings...)
	processed.Actions = append(processed.Actions, responseHeaderResult.Actions...)
	applyAuditResult(&auditEvent, processed)
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = errorCodeValue(err)
		fail(w, http.StatusBadGateway, errorCode(err))
		return
	}
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
		streamResult, err := h.streamResponse(w, response, vault, route.MaxResponseBytes, processed.Protocol)
		processed.Findings = append(processed.Findings, streamResult.Findings...)
		processed.Actions = append(processed.Actions, streamResult.Actions...)
		applyAuditResult(&auditEvent, processed)
		if err != nil {
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
	responseResult, err := pipeline.ProcessResponseDetailed(processed.Protocol, responseContentType, responseBody, h.scanner, vault)
	processed.Findings = append(processed.Findings, responseResult.Findings...)
	for range responseResult.Findings {
		processed.Actions = append(processed.Actions, domain.ActionBlock)
	}
	applyAuditResult(&auditEvent, processed)
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
	_, _ = w.Write(responseResult.Body)
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

// MCP configuration URLs identify the complete transport endpoint rather than
// an API base. The local canonical /mcp suffix exists only so Core can select
// the strict adapter and must never be appended to the fixed upstream path.
func protectedTargetPath(protocolType domain.Protocol, basePath, endpoint string) string {
	if protocolType == domain.ProtocolMCPHTTP || protocolType == domain.ProtocolMCPStreamable {
		return basePath
	}
	return joinBasePath(basePath, endpoint)
}

func (h *Handler) streamResponse(w http.ResponseWriter, response *http.Response, vault *redactor.Vault, maxBytes int64, protocolType domain.Protocol) (pipeline.TextResult, error) {
	var result pipeline.TextResult
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		fail(w, http.StatusInternalServerError, "STREAM_DEADLINE_FAILURE")
		return result, domain.NewError(domain.ErrInvalidContract, "stream response", "cannot clear streaming write deadline")
	}
	maxEventBytes := int64(1 << 20)
	if maxBytes < maxEventBytes {
		maxEventBytes = maxBytes
	}
	processor, err := pipeline.NewSSEProcessor(protocolType, h.scanner, vault, int(maxEventBytes), 512)
	if err != nil {
		fail(w, http.StatusForbidden, errorCode(err))
		return result, err
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
				return processor.Result(), err
			}
			processed, processErr := processor.Push(buffer[:read])
			if processErr != nil {
				failBeforeWrite(http.StatusForbidden, errorCode(processErr))
				return processor.Result(), processErr
			}
			if err := writeChunk(processed); err != nil {
				return processor.Result(), err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			failBeforeWrite(http.StatusBadGateway, "UPSTREAM_FAILURE")
			return processor.Result(), readErr
		}
	}
	tail, err := processor.Close()
	if err != nil {
		failBeforeWrite(http.StatusForbidden, errorCode(err))
		return processor.Result(), err
	}
	if err := writeChunk(tail); err != nil {
		return processor.Result(), err
	}
	if !wroteHeader {
		copyHeaders(w.Header(), response.Header)
		w.Header().Del("Content-Length")
		secureResponseHeaders(w.Header())
		w.WriteHeader(response.StatusCode)
	}
	return processor.Result(), nil
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

func splitCapabilityPath(endpoint string) (string, string, bool) {
	rest := strings.TrimPrefix(endpoint, "/__veil/")
	if rest == endpoint {
		return "", "", false
	}
	capability, suffix, found := strings.Cut(rest, "/")
	if !found || capability == "" || suffix == "" {
		return "", "", false
	}
	return capability, "/" + suffix, true
}

func routeAllowsMethod(protocolType domain.Protocol, method string) bool {
	return method == http.MethodPost || protocolType == domain.ProtocolMCPStreamable && (method == http.MethodGet || method == http.MethodDelete) || protocolType == domain.ProtocolMCPLegacySSE && method == http.MethodGet
}

func allowedMethods(protocolType domain.Protocol) string {
	if protocolType == domain.ProtocolMCPStreamable {
		return http.MethodDelete + ", " + http.MethodGet + ", " + http.MethodPost
	}
	if protocolType == domain.ProtocolMCPLegacySSE {
		return http.MethodGet + ", " + http.MethodPost
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
func requestsProtocolUpgrade(header http.Header) bool {
	if len(header.Values("Upgrade")) != 0 {
		return true
	}
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
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

func validateRequestHeaderBounds(headers http.Header) error {
	valueCount := 0
	totalBytes := 0
	for key, values := range headers {
		valueCount += len(values)
		totalBytes += len(key)
		if valueCount > maxRequestHeaders {
			return domain.NewError(domain.ErrInvalidContract, "scan request headers", "request has too many headers")
		}
		for _, value := range values {
			totalBytes += len(value)
			if totalBytes > maxRequestHeaderBytes {
				return domain.NewError(domain.ErrInvalidContract, "scan request headers", "request headers exceed their size limit")
			}
		}
	}
	return nil
}

func validateRequestQuery(rawQuery string) error {
	if len(rawQuery) > maxRequestQueryBytes {
		return domain.NewError(domain.ErrInvalidContract, "scan request query", "request query exceeds its size limit")
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return domain.NewError(domain.ErrInvalidContract, "scan request query", "request query is malformed")
	}
	valueCount := 0
	for _, entries := range values {
		valueCount += len(entries)
		if valueCount > maxRequestQueryValues {
			return domain.NewError(domain.ErrInvalidContract, "scan request query", "request query has too many values")
		}
	}
	return nil
}

func processRequestHeaders(ctx pipeline.Context, headers http.Header, scanner detector.ContentScanner, engine policy.Engine, vault *redactor.Vault) (pipeline.TextResult, error) {
	var aggregate pipeline.TextResult
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for keyIndex, key := range keys {
		if isProviderCredentialHeader(key) {
			continue
		}
		canonicalKey := http.CanonicalHeaderKey(key)
		keyResult, err := pipeline.ProcessText(ctx, "/request/headers/key/"+strconv.Itoa(keyIndex), canonicalKey, scanner, engine, vault)
		aggregate.Findings = append(aggregate.Findings, keyResult.Findings...)
		aggregate.Actions = append(aggregate.Actions, keyResult.Actions...)
		if err != nil {
			return aggregate, err
		}
		for _, action := range keyResult.Actions {
			if action != domain.ActionAllow {
				return aggregate, domain.NewError(domain.ErrPolicyBlocked, "scan request headers", "sensitive header names cannot be safely rewritten")
			}
		}
		values := headers[key]
		for index, value := range values {
			processed, err := pipeline.ProcessText(ctx, "/request/headers/value/"+strconv.Itoa(keyIndex)+"/"+strconv.Itoa(index), value, scanner, engine, vault)
			aggregate.Findings = append(aggregate.Findings, processed.Findings...)
			aggregate.Actions = append(aggregate.Actions, processed.Actions...)
			if err != nil {
				return aggregate, err
			}
			headers[key][index] = processed.Text
		}
	}
	return aggregate, nil
}

func processRequestQuery(ctx pipeline.Context, requestURL *url.URL, scanner detector.ContentScanner, engine policy.Engine, vault *redactor.Vault) (pipeline.TextResult, error) {
	var aggregate pipeline.TextResult
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return aggregate, domain.NewError(domain.ErrInvalidContract, "scan request query", "request query is malformed")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for keyIndex, key := range keys {
		if strings.EqualFold(key, "key") {
			continue
		}
		keyResult, err := pipeline.ProcessText(ctx, "/request/query/key/"+strconv.Itoa(keyIndex), key, scanner, engine, vault)
		aggregate.Findings = append(aggregate.Findings, keyResult.Findings...)
		aggregate.Actions = append(aggregate.Actions, keyResult.Actions...)
		if err != nil {
			return aggregate, err
		}
		for _, action := range keyResult.Actions {
			if action != domain.ActionAllow {
				return aggregate, domain.NewError(domain.ErrPolicyBlocked, "scan request query", "sensitive query keys cannot be safely rewritten")
			}
		}
		for valueIndex, value := range values[key] {
			valueResult, err := pipeline.ProcessText(ctx, "/request/query/value/"+strconv.Itoa(keyIndex)+"/"+strconv.Itoa(valueIndex), value, scanner, engine, vault)
			aggregate.Findings = append(aggregate.Findings, valueResult.Findings...)
			aggregate.Actions = append(aggregate.Actions, valueResult.Actions...)
			if err != nil {
				return aggregate, err
			}
			values[key][valueIndex] = valueResult.Text
		}
	}
	requestURL.RawQuery = values.Encode()
	return aggregate, nil
}

func isProviderCredentialHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Authorization", "X-Api-Key", "X-Goog-Api-Key", "X-Amz-Security-Token", "X-Amz-Date", "X-Amz-Content-Sha256":
		return true
	}
	return false
}

func processResponseHeaders(headers http.Header, scanner detector.ContentScanner, vault *redactor.Vault) (pipeline.TextResult, error) {
	var result pipeline.TextResult
	if scanner == nil {
		return result, domain.NewError(domain.ErrDetectorFailure, "scan response headers", "content scanner is unavailable")
	}
	valueCount := 0
	totalBytes := 0
	for key, values := range headers {
		valueCount += len(values)
		totalBytes += len(key)
		if valueCount > maxResponseHeaders {
			return result, domain.NewError(domain.ErrInvalidContract, "scan response headers", "provider response has too many headers")
		}
		for index, value := range values {
			totalBytes += len(value)
			if totalBytes > maxResponseHeaderBytes {
				return result, domain.NewError(domain.ErrInvalidContract, "scan response headers", "provider response headers exceed their size limit")
			}
			matches, err := detector.ScanContent(scanner, "/response/headers/"+http.CanonicalHeaderKey(key), key+": "+value)
			if err != nil {
				return result, domain.NewError(domain.ErrDetectorFailure, "scan response headers", "provider response header scan failed")
			}
			if len(matches) != 0 {
				for _, match := range matches {
					result.Findings = append(result.Findings, match.Finding)
					result.Actions = append(result.Actions, domain.ActionBlock)
				}
				return result, domain.NewError(domain.ErrPolicyBlocked, "scan response headers", "provider response header contains sensitive content")
			}
			restored, err := vault.Restore(value)
			if err != nil {
				return result, err
			}
			headers[key][index] = restored
		}
	}
	return result, nil
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
	event.FindingCount = 0
	event.FindingTypes = nil
	event.Severity = ""
	event.Action = domain.ActionAllow
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
