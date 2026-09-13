package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/pipeline"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/security"
	"github.com/agentveil/agentveil/internal/session"
	veilstream "github.com/agentveil/agentveil/internal/stream"
)

const legacySSEPostPrefix = "/mcp-legacy/"

func (h *Handler) serveLegacySSE(w http.ResponseWriter, r *http.Request, route configuredRoute, routeID, endpoint, sessionID, routeToken string, authorization session.Authorization, interactive bool, auditEvent *domain.AuditEvent) {
	if requestsProtocolUpgrade(r.Header) || len(r.Header.Values("Cookie")) != 0 {
		wipe(authorization.Secret)
		blockLegacyRequest(w, auditEvent, http.StatusForbidden, domain.ErrUnknownProtocol)
		return
	}
	if err := validateRequestHeaderBounds(r.Header); err != nil {
		wipe(authorization.Secret)
		blockLegacyRequest(w, auditEvent, http.StatusRequestHeaderFieldsTooLarge, domain.ErrInvalidContract)
		return
	}
	if r.URL.RawQuery != "" || validateRequestQuery(r.URL.RawQuery) != nil || !routeAllowsMethod(route.Protocol, r.Method) {
		wipe(authorization.Secret)
		if !routeAllowsMethod(route.Protocol, r.Method) {
			w.Header().Set("Allow", allowedMethods(route.Protocol))
			blockLegacyRequest(w, auditEvent, http.StatusMethodNotAllowed, domain.ErrUnsupportedMethod)
		} else {
			blockLegacyRequest(w, auditEvent, http.StatusBadRequest, domain.ErrInvalidContract)
		}
		return
	}
	if r.Method == http.MethodGet {
		h.serveLegacySSEGet(w, r, route, routeID, endpoint, sessionID, routeToken, authorization, interactive, auditEvent)
		return
	}
	wipe(authorization.Secret)
	h.serveLegacySSEPost(w, r, route, routeID, endpoint, sessionID, authorization, interactive, auditEvent)
}

func (h *Handler) serveLegacySSEGet(w http.ResponseWriter, r *http.Request, route configuredRoute, routeID, endpoint, sessionID, routeToken string, authorization session.Authorization, interactive bool, auditEvent *domain.AuditEvent) {
	if endpoint != "/mcp" {
		wipe(authorization.Secret)
		blockLegacyRequest(w, auditEvent, http.StatusForbidden, domain.ErrUnknownProtocol)
		return
	}
	accept, uniqueAccept := uniqueHeaderValue(r.Header, "Accept")
	if !uniqueAccept || !acceptsMediaType(accept, "text/event-stream") {
		wipe(authorization.Secret)
		blockLegacyRequest(w, auditEvent, http.StatusBadRequest, domain.ErrUnknownProtocol)
		return
	}
	body, err := readLimited(r.Body, route.MaxRequestBytes)
	if err != nil || len(body) != 0 {
		wipe(authorization.Secret)
		blockLegacyRequest(w, auditEvent, http.StatusBadRequest, domain.ErrUnknownProtocol)
		return
	}
	vault, err := redactor.NewVault(authorization.Secret, route.VaultLimits)
	wipe(authorization.Secret)
	if err != nil {
		blockLegacyRequest(w, auditEvent, http.StatusInternalServerError, domain.ErrInvalidContract)
		return
	}
	vaultOwned := true
	defer func() {
		if vaultOwned {
			vault.Destroy()
		}
	}()
	target := cloneURL(route.Upstream)
	requestContext, cancel := legacyRequestContext(r.Context(), authorization.Context)
	defer cancel()
	upstreamRequest, err := http.NewRequestWithContext(requestContext, http.MethodGet, target.String(), nil)
	if err != nil {
		blockLegacyRequest(w, auditEvent, http.StatusBadGateway, domain.ErrInvalidContract)
		return
	}
	copyHeaders(upstreamRequest.Header, r.Header)
	stripLocalCapabilityHeaders(upstreamRequest.Header, route)
	upstreamRequest.Header.Set("Accept-Encoding", "identity")
	requestResult, err := processRequestHeaders(legacyPipelineContext(route, interactive, requestContext), upstreamRequest.Header, h.scanner, route.Policy, vault)
	applyLegacyTextResult(auditEvent, requestResult)
	if err == nil {
		err = route.AuthApplier.Apply(upstreamRequest, legacyAuthStrategy(route))
	}
	if err != nil {
		blockLegacyError(w, auditEvent, http.StatusForbidden, err)
		return
	}
	client := *route.client
	client.Timeout = 0
	client.CheckRedirect = exactLegacyRedirect(route, upstreamRequest)
	response, err := client.Do(upstreamRequest)
	if err != nil {
		blockLegacyCode(w, auditEvent, http.StatusBadGateway, "UPSTREAM_FAILURE")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Set-Cookie")) != 0 {
		blockLegacyRequest(w, auditEvent, http.StatusBadGateway, domain.ErrUnknownProtocol)
		return
	}
	responseResult, err := processResponseHeaders(response.Header, h.scanner, vault)
	applyLegacyTextResult(auditEvent, responseResult)
	encoding, uniqueEncoding := uniqueHeaderValue(response.Header, "Content-Encoding")
	contentType, uniqueContentType := uniqueHeaderValue(response.Header, "Content-Type")
	if err != nil || !uniqueEncoding || strings.TrimSpace(encoding) != "" && !strings.EqualFold(encoding, "identity") || !uniqueContentType || !protocol.MediaTypeIs(contentType, "text/event-stream") {
		if err != nil {
			blockLegacyError(w, auditEvent, http.StatusBadGateway, err)
		} else {
			blockLegacyRequest(w, auditEvent, http.StatusBadGateway, domain.ErrUnknownProtocol)
		}
		return
	}
	channelID, streamResult, err := h.streamLegacySSE(w, response, route, routeID, sessionID, routeToken, authorization, vault)
	applyLegacyTextResult(auditEvent, streamResult)
	if channelID != "" {
		vaultOwned = false
		defer route.LegacySessions.Close(channelID, sessionID, routeID)
	}
	if err != nil {
		auditEvent.Action = domain.ActionBlock
		auditEvent.ErrorCode = errorCodeValue(err)
	}
}

func (h *Handler) serveLegacySSEPost(w http.ResponseWriter, r *http.Request, route configuredRoute, routeID, endpoint, sessionID string, authorization session.Authorization, interactive bool, auditEvent *domain.AuditEvent) {
	channelID := strings.TrimPrefix(endpoint, legacySSEPostPrefix)
	if channelID == endpoint || channelID == "" || strings.Contains(channelID, "/") || !routeIDPattern.MatchString(channelID) {
		blockLegacyRequest(w, auditEvent, http.StatusForbidden, domain.ErrUnknownProtocol)
		return
	}
	binding, release, ok := route.LegacySessions.Acquire(r.Context(), channelID, sessionID, routeID)
	if !ok {
		blockLegacyRequest(w, auditEvent, http.StatusUnauthorized, domain.ErrUnauthorizedRoute)
		return
	}
	defer release()
	requestContext, cancel := legacyRequestContext(r.Context(), binding.Context)
	defer cancel()
	body, err := readLimited(r.Body, route.MaxRequestBytes)
	if err != nil {
		blockLegacyCode(w, auditEvent, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
		return
	}
	processed, err := pipeline.ProcessForProtocol(legacyPipelineContext(route, interactive, requestContext), domain.ProtocolMCPLegacySSE, "/mcp", r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body, h.scanner, route.Policy, binding.Vault)
	applyAuditResult(auditEvent, processed)
	if err != nil {
		blockLegacyError(w, auditEvent, http.StatusForbidden, err)
		return
	}
	upstreamRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost, binding.Upstream.String(), bytes.NewReader(processed.Body))
	if err != nil {
		blockLegacyCode(w, auditEvent, http.StatusBadGateway, "UPSTREAM_REQUEST_FAILED")
		return
	}
	copyHeaders(upstreamRequest.Header, r.Header)
	stripLocalCapabilityHeaders(upstreamRequest.Header, route)
	upstreamRequest.Header.Del("Content-Encoding")
	upstreamRequest.Header.Set("Accept-Encoding", "identity")
	upstreamRequest.ContentLength = int64(len(processed.Body))
	headerResult, err := processRequestHeaders(legacyPipelineContext(route, interactive, requestContext), upstreamRequest.Header, h.scanner, route.Policy, binding.Vault)
	processed.Findings = append(processed.Findings, headerResult.Findings...)
	processed.Actions = append(processed.Actions, headerResult.Actions...)
	applyAuditResult(auditEvent, processed)
	if err == nil {
		err = route.AuthApplier.Apply(upstreamRequest, legacyAuthStrategy(route))
	}
	if err != nil {
		blockLegacyError(w, auditEvent, http.StatusForbidden, err)
		return
	}
	client := *route.client
	client.CheckRedirect = exactLegacyRedirect(route, upstreamRequest)
	response, err := client.Do(upstreamRequest)
	if err != nil {
		blockLegacyCode(w, auditEvent, http.StatusBadGateway, "UPSTREAM_FAILURE")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || len(response.Header.Values("Set-Cookie")) != 0 {
		blockLegacyRequest(w, auditEvent, http.StatusBadGateway, domain.ErrUnknownProtocol)
		return
	}
	responseResult, err := processResponseHeaders(response.Header, h.scanner, binding.Vault)
	applyLegacyTextResult(auditEvent, responseResult)
	encoding, uniqueEncoding := uniqueHeaderValue(response.Header, "Content-Encoding")
	if err != nil || !uniqueEncoding || strings.TrimSpace(encoding) != "" && !strings.EqualFold(encoding, "identity") {
		if err != nil {
			blockLegacyError(w, auditEvent, http.StatusBadGateway, err)
		} else {
			blockLegacyRequest(w, auditEvent, http.StatusBadGateway, domain.ErrUnsupportedEncoding)
		}
		return
	}
	responseBody, err := readLimited(response.Body, route.MaxResponseBytes)
	if err != nil || len(responseBody) != 0 {
		blockLegacyRequest(w, auditEvent, http.StatusBadGateway, domain.ErrUnknownProtocol)
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Content-Length")
	secureResponseHeaders(w.Header())
	w.WriteHeader(response.StatusCode)
}

func (h *Handler) streamLegacySSE(w http.ResponseWriter, response *http.Response, route configuredRoute, routeID, sessionID, routeToken string, authorization session.Authorization, vault *redactor.Vault) (string, pipeline.TextResult, error) {
	var result pipeline.TextResult
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		fail(w, http.StatusInternalServerError, "STREAM_DEADLINE_FAILURE")
		return "", result, err
	}
	maxEventBytes := int64(veilstream.MaxSSEEventBytes)
	if route.MaxResponseBytes < maxEventBytes {
		maxEventBytes = route.MaxResponseBytes
	}
	decoder, err := veilstream.NewDecoder(int(maxEventBytes))
	if err != nil {
		fail(w, http.StatusForbidden, errorCode(err))
		return "", result, err
	}
	processor, err := pipeline.NewSSEProcessor(domain.ProtocolMCPLegacySSE, h.scanner, vault, int(maxEventBytes), 512)
	if err != nil {
		fail(w, http.StatusForbidden, errorCode(err))
		return "", result, err
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
	var channel LegacySSEBinding
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > route.MaxResponseBytes {
				err := domain.NewError(domain.ErrInvalidContract, "read legacy SSE", "response body limit exceeded")
				failBeforeWrite(http.StatusBadGateway, "RESPONSE_TOO_LARGE")
				return channel.ID, processor.Result(), err
			}
			events, decodeErr := decoder.Push(buffer[:read])
			if decodeErr != nil {
				failBeforeWrite(http.StatusForbidden, errorCode(decodeErr))
				return channel.ID, processor.Result(), decodeErr
			}
			for _, event := range events {
				if channel.ID == "" {
					if event.Event == "" && event.Data == "" {
						continue
					}
					if event.Event != "endpoint" || strings.TrimSpace(event.Data) == "" {
						err := domain.NewError(domain.ErrUnknownProtocol, "process legacy SSE", "first transport event is not an endpoint")
						failBeforeWrite(http.StatusForbidden, errorCode(err))
						return "", processor.Result(), err
					}
					providerEndpoint, resolveErr := resolveLegacyProviderEndpoint(route, event.Data)
					if resolveErr != nil {
						failBeforeWrite(http.StatusForbidden, errorCode(resolveErr))
						return "", processor.Result(), resolveErr
					}
					coreEndpoint, coreErr := legacyCoreEndpoint(authorization.CoreEndpoint)
					if coreErr != nil {
						failBeforeWrite(http.StatusForbidden, errorCode(coreErr))
						return "", processor.Result(), coreErr
					}
					channel, resolveErr = route.LegacySessions.Open(sessionID, routeID, providerEndpoint, authorization.ExpiresAt, authorization.Context, vault)
					if resolveErr != nil {
						failBeforeWrite(http.StatusServiceUnavailable, errorCode(resolveErr))
						return "", processor.Result(), resolveErr
					}
					event.Data = coreEndpoint + "/route/" + routeID + "/__veil/" + url.PathEscape(EncodeCapability(sessionID, routeToken)) + legacySSEPostPrefix + channel.ID
					if err := writeChunk(veilstream.Encode([]veilstream.Event{event})); err != nil {
						return channel.ID, processor.Result(), err
					}
					continue
				}
				if event.Event == "endpoint" || event.Event != "" && event.Event != "message" {
					err := domain.NewError(domain.ErrUnknownProtocol, "process legacy SSE", "stream contains an unsupported transport event")
					failBeforeWrite(http.StatusForbidden, errorCode(err))
					return channel.ID, processor.Result(), err
				}
				processed, processErr := processor.Push(veilstream.Encode([]veilstream.Event{event}))
				if processErr != nil {
					failBeforeWrite(http.StatusForbidden, errorCode(processErr))
					return channel.ID, processor.Result(), processErr
				}
				if err := writeChunk(processed); err != nil {
					return channel.ID, processor.Result(), err
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			failBeforeWrite(http.StatusBadGateway, "UPSTREAM_FAILURE")
			return channel.ID, processor.Result(), readErr
		}
	}
	if err := decoder.Close(); err != nil {
		failBeforeWrite(http.StatusForbidden, errorCode(err))
		return channel.ID, processor.Result(), err
	}
	if channel.ID == "" {
		err := domain.NewError(domain.ErrUnknownProtocol, "process legacy SSE", "stream ended before advertising an endpoint")
		failBeforeWrite(http.StatusForbidden, errorCode(err))
		return "", processor.Result(), err
	}
	tail, err := processor.Close()
	if err != nil {
		failBeforeWrite(http.StatusForbidden, errorCode(err))
		return channel.ID, processor.Result(), err
	}
	if err := writeChunk(tail); err != nil {
		return channel.ID, processor.Result(), err
	}
	return channel.ID, processor.Result(), nil
}

func legacyCoreEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || !security.ValidLoopbackAuthority(parsed.Host) {
		return "", domain.NewError(domain.ErrInvalidContract, "rewrite legacy SSE endpoint", "session Core endpoint is invalid")
	}
	return parsed.String(), nil
}

func resolveLegacyProviderEndpoint(route configuredRoute, advertised string) (*url.URL, error) {
	reference, err := url.Parse(strings.TrimSpace(advertised))
	if err != nil {
		return nil, domain.NewError(domain.ErrUpstreamDenied, "resolve legacy SSE endpoint", "advertised endpoint is invalid")
	}
	resolved := route.Upstream.ResolveReference(reference)
	if !validLegacySSEUpstream(resolved) {
		return nil, domain.NewError(domain.ErrUpstreamDenied, "resolve legacy SSE endpoint", "advertised endpoint is unsafe")
	}
	if err := route.allowlist.ValidateURL(resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

func exactLegacyRedirect(route configuredRoute, original *http.Request) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, _ []*http.Request) error {
		if err := route.allowlist.ValidateURL(request.URL); err != nil {
			return err
		}
		if request.Method != original.Method || request.URL.EscapedPath() != original.URL.EscapedPath() || request.URL.RawQuery != original.URL.RawQuery {
			return domain.NewError(domain.ErrUpstreamDenied, "validate legacy redirect", "redirect changed the protected endpoint")
		}
		return nil
	}
}

func legacyRequestContext(requestContext, channelContext context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(channelContext)
	stop := context.AfterFunc(requestContext, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func legacyPipelineContext(route configuredRoute, interactive bool, requestContext context.Context) pipeline.Context {
	surfaceID := route.SurfaceID
	if surfaceID == "" {
		surfaceID = route.ID
	}
	return pipeline.Context{AgentID: route.AgentID, Workspace: route.Workspace, Provider: route.Upstream.Hostname(), SurfaceID: surfaceID, Interactive: interactive, RequestContext: requestContext, Approver: route.Approver}
}

func legacyAuthStrategy(route configuredRoute) domain.AuthStrategy {
	auth := route.Auth
	if auth.Type == "" {
		auth.Type = domain.AuthPassthrough
	}
	return auth
}

func stripLocalCapabilityHeaders(header http.Header, route configuredRoute) {
	header.Del(HeaderSession)
	header.Del(HeaderRouteToken)
	if route.CapabilityHeader != "" {
		header.Del(route.CapabilityHeader)
	}
}

func acceptsMediaType(value, expected string) bool {
	for _, item := range strings.Split(value, ",") {
		if protocol.MediaTypeIs(strings.TrimSpace(item), expected) {
			return true
		}
	}
	return false
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func applyLegacyTextResult(event *domain.AuditEvent, result pipeline.TextResult) {
	event.FindingCount += len(result.Findings)
	for _, finding := range result.Findings {
		event.FindingTypes = append(event.FindingTypes, finding.Category)
	}
	for _, action := range result.Actions {
		if actionRank(action) > actionRank(event.Action) {
			event.Action = action
		}
	}
}

func blockLegacyRequest(w http.ResponseWriter, event *domain.AuditEvent, status int, code domain.ErrorCode) {
	event.Action = domain.ActionBlock
	event.ErrorCode = code
	fail(w, status, string(code))
}

func blockLegacyError(w http.ResponseWriter, event *domain.AuditEvent, status int, err error) {
	event.Action = domain.ActionBlock
	event.ErrorCode = errorCodeValue(err)
	fail(w, status, errorCode(err))
}

func blockLegacyCode(w http.ResponseWriter, event *domain.AuditEvent, status int, code string) {
	event.Action = domain.ActionBlock
	event.ErrorCode = domain.ErrorCode(code)
	fail(w, status, code)
}
