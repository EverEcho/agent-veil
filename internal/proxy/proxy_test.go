package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/session"
)

type blockingRequestBody struct {
	started              chan struct{}
	closed               chan struct{}
	startOnce, closeOnce sync.Once
}

func (b *blockingRequestBody) Read([]byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.closed
	return 0, errors.New("request body closed")
}

func (b *blockingRequestBody) Close() error {
	b.startOnce.Do(func() { close(b.started) })
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

func TestEndToEndProviderOnlyReceivesRedactedContent(t *testing.T) {
	var providerBody string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		providerBody = string(payload)
		var request map[string]any
		_ = json.Unmarshal(payload, &request)
		response, _ := json.Marshal(map[string]any{"output_text": request["input"]})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, err := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()
	request, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/route/primary/v1/responses", strings.NewReader(`{"input":"email dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || strings.Contains(providerBody, "dev@example.com") || !strings.Contains(string(result), "dev@example.com") {
		t.Fatalf("status=%d provider=%s client=%s", response.StatusCode, providerBody, result)
	}
}

func TestEndToEndProtocolMatrixOnlySendsRedactedContentToProvider(t *testing.T) {
	tests := []struct {
		name     string
		protocol domain.Protocol
		endpoint string
		request  string
		response func(string) any
		mcp      bool
	}{
		{"openai-chat", domain.ProtocolOpenAIChat, "/v1/chat/completions", `{"messages":[{"role":"user","content":"email dev@example.com"}]}`, func(value string) any {
			return map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": value}}}}
		}, false},
		{"openai-responses", domain.ProtocolOpenAIResponses, "/v1/responses", `{"input":"email dev@example.com"}`, func(value string) any {
			return map[string]any{"output_text": value}
		}, false},
		{"anthropic", domain.ProtocolAnthropic, "/v1/messages", `{"messages":[{"role":"user","content":"email dev@example.com"}]}`, func(value string) any {
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": value}}}
		}, false},
		{"gemini", domain.ProtocolGemini, "/v1beta/models/gemini-2.5-pro:generateContent", `{"contents":[{"role":"user","parts":[{"text":"email dev@example.com"}]}]}`, func(value string) any {
			return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": value}}}}}}
		}, false},
		{"mcp-http", domain.ProtocolMCPHTTP, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"email":"dev@example.com"}}}`, func(value string) any {
			return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": value}}}}
		}, false},
		{"mcp-streamable", domain.ProtocolMCPStreamable, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"email":"dev@example.com"}}}`, func(value string) any {
			return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": value}}}}
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var providerBody string
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				payload, _ := io.ReadAll(request.Body)
				providerBody = string(payload)
				placeholder := firstVeilPlaceholder(providerBody)
				if placeholder == "" || strings.Contains(providerBody, "dev@example.com") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				response, _ := json.Marshal(test.response("provider echo " + placeholder))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(response)
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: test.protocol, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			proxyServer := httptest.NewServer(handler)
			defer proxyServer.Close()
			request, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/route/primary"+test.endpoint, strings.NewReader(test.request))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			if test.mcp {
				request.Header.Set("Accept", "application/json, text/event-stream")
				request.Header.Set("MCP-Protocol-Version", "2025-03-26")
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			result, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK || providerBody == "" || strings.Contains(providerBody, "dev@example.com") || firstVeilPlaceholder(providerBody) == "" || !strings.Contains(string(result), "provider echo dev@example.com") || firstVeilPlaceholder(string(result)) != "" {
				t.Fatalf("protocol=%s status=%d provider=%s client=%s", test.protocol, response.StatusCode, providerBody, result)
			}
		})
	}
}

func firstVeilPlaceholder(value string) string {
	start := strings.Index(value, "[[VEIL_")
	if start < 0 {
		return ""
	}
	end := strings.Index(value[start:], "]]")
	if end < 0 {
		return ""
	}
	return value[start : start+end+2]
}

func TestRequestHeadersPassThroughWithoutPrivacyRewriting(t *testing.T) {
	var providerHeader string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerHeader = r.Header.Get("X-Request-Context")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo-Context", providerHeader)
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-Context", "contact dev@example.com")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerHeader != "contact dev@example.com" || recorder.Header().Get("X-Echo-Context") != providerHeader || recorder.Body.String() != `{"output_text":"safe"}` {
		t.Fatalf("status=%d provider header=%q response header=%q body=%s", recorder.Code, providerHeader, recorder.Header().Get("X-Echo-Context"), recorder.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].FindingCount != 0 || auditor.events[0].Action != domain.ActionAllow {
		t.Fatalf("audit=%+v", auditor.events)
	}
}

func TestBlockPolicyDoesNotApplyToTransportHeaders(t *testing.T) {
	providerCalls := 0
	var providerHeader string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		providerCalls++
		providerHeader = request.Header.Get("X-Request-Context")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionBlock}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-Context", "contact dev@example.com")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerCalls != 1 || providerHeader != "contact dev@example.com" || len(auditor.events) != 1 || auditor.events[0].FindingCount != 0 || auditor.events[0].Action != domain.ActionAllow || auditor.events[0].ErrorCode != "" {
		t.Fatalf("status=%d calls=%d audit=%+v body=%s", recorder.Code, providerCalls, auditor.events, recorder.Body.String())
	}
}

func TestOpaqueRequestHeaderNamePassesThrough(t *testing.T) {
	providerCalls := 0
	var providerValue string
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		providerCalls++
		providerValue = request.Header.Get("4111111111111111")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("4111111111111111", "value")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerCalls != 1 || providerValue != "value" || len(auditor.events) != 1 || auditor.events[0].FindingCount != 0 || auditor.events[0].Action != domain.ActionAllow {
		t.Fatalf("status=%d calls=%d audit=%+v body=%s", recorder.Code, providerCalls, auditor.events, recorder.Body.String())
	}
}

func TestPassthroughProviderCredentialHeaderIsNotRedacted(t *testing.T) {
	const credential = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlMTIzNDU2"
	var providerAuthorization string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", credential)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerAuthorization != credential {
		t.Fatalf("status=%d authorization=%q", recorder.Code, providerAuthorization)
	}
}

func TestRequestHeaderBoundsFailBeforeProvider(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Oversized", strings.Repeat("a", maxRequestHeaderBytes+1))
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestHeaderFieldsTooLarge || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrInvalidContract)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func TestRequestQueryPassesThroughWithoutPrivacyRewriting(t *testing.T) {
	var providerQuery string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerQuery = r.URL.Query().Get("context")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 4, MaxOriginalBytes: 256}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses?context=contact%20dev%40example.com", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerQuery != "contact dev@example.com" || recorder.Body.String() != `{"output_text":"safe"}` {
		t.Fatalf("status=%d provider query=%q body=%s", recorder.Code, providerQuery, recorder.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].FindingCount != 0 || auditor.events[0].Action != domain.ActionAllow {
		t.Fatalf("audit=%+v", auditor.events)
	}
}

func TestOpaqueRequestQueryKeyPassesThrough(t *testing.T) {
	providerCalls := 0
	var providerQuery string
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		providerCalls++
		providerQuery = request.URL.RawQuery
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 4, MaxOriginalBytes: 256}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses?ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890=value", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerCalls != 1 || providerQuery != "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890=value" || len(auditor.events) != 1 || auditor.events[0].FindingCount != 0 || auditor.events[0].Action != domain.ActionAllow {
		t.Fatalf("status=%d calls=%d audit=%+v body=%s", recorder.Code, providerCalls, auditor.events, recorder.Body.String())
	}
}

func TestRequestQueryValidation(t *testing.T) {
	if err := validateRequestQuery("unsafe;query=value"); err == nil {
		t.Fatal("malformed query accepted")
	}
	if err := validateRequestQuery("q=" + strings.Repeat("a", maxRequestQueryBytes)); err == nil {
		t.Fatal("oversized query accepted")
	}
}

func TestProxyChunkedScannerFindsEntityAcrossLongContextBoundary(t *testing.T) {
	var providerBody string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		providerBody = string(payload)
		var request map[string]any
		_ = json.Unmarshal(payload, &request)
		response, _ := json.Marshal(map[string]any{"output_text": request["input"]})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 128 << 10, MaxResponseBytes: 128 << 10, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Repeat("a", defaultChunkBytes-7) + " " + "dev@example.com"
	payload, _ := json.Marshal(map[string]any{"input": input})
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(providerBody, "dev@example.com") || !strings.Contains(recorder.Body.String(), "dev@example.com") {
		t.Fatalf("status=%d provider contains email=%v response contains email=%v body=%s", recorder.Code, strings.Contains(providerBody, "dev@example.com"), strings.Contains(recorder.Body.String(), "dev@example.com"), recorder.Body.String())
	}
}

type finalBodySigner struct{ sawOriginal bool }

func (s *finalBodySigner) Apply(request *http.Request) error {
	body, _ := io.ReadAll(request.Body)
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	s.sawOriginal = strings.Contains(string(body), "dev@example.com")
	request.Header.Set("X-Signed", "yes")
	return nil
}

type recordingAuditor struct{ events []domain.AuditEvent }

func (a *recordingAuditor) Append(event domain.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadlines = append(r.deadlines, deadline)
	return nil
}

type fixedCredentials map[string]string

func (c fixedCredentials) Resolve(source string) (string, error) { return c[source], nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type recordingCookieJar struct {
	setCalls int
}

func (*recordingCookieJar) Cookies(*url.URL) []*http.Cookie {
	return []*http.Cookie{{Name: "implicit", Value: "credential"}}
}
func (j *recordingCookieJar) SetCookies(*url.URL, []*http.Cookie) {
	j.setCalls++
}

func TestProxyRejectsUnboundedRoutesAndBodies(t *testing.T) {
	manager := session.NewManager()
	upstream, _ := url.Parse("https://api.example")
	base := Route{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}
	routes := make([]Route, MaxProxyRoutes+1)
	for index := range routes {
		routes[index] = base
	}
	for _, candidate := range [][]Route{
		nil,
		routes,
		{{ID: "unsafe/route", Upstream: upstream, MaxRequestBytes: 4096, MaxResponseBytes: 4096}},
		{{ID: "primary", Upstream: upstream, MaxRequestBytes: MaxProxyBodyBytes + 1, MaxResponseBytes: 4096}},
		{{ID: "primary", Upstream: upstream, MaxRequestBytes: 4096, MaxResponseBytes: MaxProxyBodyBytes + 1}},
	} {
		if _, err := NewHandler(manager, candidate, http.DefaultClient); err == nil {
			t.Fatalf("unbounded proxy configuration accepted: routes=%d", len(candidate))
		}
	}
}

func TestCopyHeadersRemovesConnectionNominatedFields(t *testing.T) {
	source := http.Header{
		"Connection": {"X-Hop, Keep-Alive"},
		"X-Hop":      {"must-not-cross"},
		"X-End":      {"safe"},
	}
	destination := make(http.Header)
	copyHeaders(destination, source)
	if destination.Get("Connection") != "" || destination.Get("X-Hop") != "" || destination.Get("Keep-Alive") != "" || destination.Get("X-End") != "safe" {
		t.Fatalf("copied headers=%v", destination)
	}
}

func TestProxyRejectsRequestProtocolUpgradesBeforeCallingProvider(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"unsafe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) || providerCalls != 0 {
		t.Fatalf("status=%d provider calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].Action != domain.ActionBlock || auditor.events[0].ErrorCode != domain.ErrUnknownProtocol {
		t.Fatalf("audit=%+v", auditor.events)
	}
}

func TestProxyRejectsProviderProtocolUpgradesBeforeForwarding(t *testing.T) {
	upstream, _ := url.Parse("https://api.example")
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Status:     "101 Switching Protocols",
			Header:     http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}},
			Body:       io.NopCloser(strings.NewReader("provider-upgrade-bytes")),
			Request:    request,
		}, nil
	})}
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, client)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) || strings.Contains(recorder.Body.String(), "provider-upgrade-bytes") || recorder.Header().Get("Upgrade") != "" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].Action != domain.ActionBlock || auditor.events[0].ErrorCode != domain.ErrUnknownProtocol {
		t.Fatalf("audit=%+v", auditor.events)
	}
}

func TestProxyDoesNotPersistOrReplayCallerCookieJarState(t *testing.T) {
	providerCookie := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	jar := &recordingCookieJar{}
	client := provider.Client()
	client.Jar = jar
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, client)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerCookie != "" || jar.setCalls != 0 {
		t.Fatalf("status=%d provider cookie=%q jar writes=%d body=%s", recorder.Code, providerCookie, jar.setCalls, recorder.Body.String())
	}
}

func TestProxyRejectsRequestCookiesAndDropsProviderCookies(t *testing.T) {
	for _, test := range []struct {
		name           string
		requestCookie  bool
		responseCookie bool
		wantStatus     int
		wantCalls      int
	}{
		{name: "request cookie", requestCookie: true, wantStatus: http.StatusForbidden},
		{name: "provider cookie", responseCookie: true, wantStatus: http.StatusOK, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerCalls := 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				providerCalls++
				if test.responseCookie {
					w.Header().Set("Set-Cookie", "provider_state=safe; Secure; HttpOnly")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"output_text":"safe"}`)
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			if test.requestCookie {
				request.Header.Set("Cookie", "provider_state=safe")
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus || providerCalls != test.wantCalls || recorder.Header().Get("Set-Cookie") != "" {
				t.Fatalf("status=%d provider calls=%d headers=%v body=%s", recorder.Code, providerCalls, recorder.Header(), recorder.Body.String())
			}
			if test.requestCookie && !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
				t.Fatalf("request cookie failure body=%s", recorder.Body.String())
			}
		})
	}
}

func TestCapabilityCarrierIsRemovedBeforeProviderAuth(t *testing.T) {
	var providerKey string
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		providerKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	strategy := domain.AuthStrategy{Type: domain.AuthAnthropicKey, Source: "environment:ANTHROPIC_API_KEY"}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolAnthropic, Upstream: upstream, Auth: strategy, AuthApplier: veilauth.Applier{Credentials: fixedCredentials{strategy.Source: "real-provider-key"}}, CapabilityHeader: "X-Api-Key", Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/messages", strings.NewReader(`{"messages":[{"role":"user","content":"safe"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Api-Key", EncodeCapability(created.Session.ID, created.Routes[0].Token))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerKey != "real-provider-key" || strings.Contains(providerKey, created.Session.ID) {
		t.Fatalf("status=%d provider key=%q", recorder.Code, providerKey)
	}
	for name, configure := range map[string]func(http.Header){
		"duplicate carrier": func(header http.Header) {
			header["X-Api-Key"] = []string{EncodeCapability(created.Session.ID, created.Routes[0].Token), EncodeCapability(created.Session.ID, created.Routes[0].Token)}
		},
		"mixed carriers": func(header http.Header) {
			header.Set("X-Api-Key", EncodeCapability(created.Session.ID, created.Routes[0].Token))
			header.Set(HeaderSession, created.Session.ID)
			header.Set(HeaderRouteToken, created.Routes[0].Token)
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/messages", strings.NewReader(`{"messages":[{"role":"user","content":"safe"}]}`))
			request.Header.Set("Content-Type", "application/json")
			configure(request.Header)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized || providerCalls != 1 {
				t.Fatalf("status=%d provider calls=%d", recorder.Code, providerCalls)
			}
		})
	}
}

func TestPathCapabilityIsRemovedWithoutReplacingProviderAuthorization(t *testing.T) {
	var providerPath, providerAuthorization string
	var providerCapabilityHeaders bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerPath = r.URL.Path
		providerAuthorization = r.Header.Get("Authorization")
		providerCapabilityHeaders = r.Header.Get(HeaderSession) != "" || r.Header.Get(HeaderRouteToken) != ""
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, CapabilityPath: true, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	capability := EncodeCapability(created.Session.ID, created.Routes[0].Token)
	request := httptest.NewRequest(http.MethodPost, "/route/primary/__veil/"+capability+"/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer provider-oauth-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerPath != "/v1/responses" || providerAuthorization != "Bearer provider-oauth-token" || providerCapabilityHeaders {
		t.Fatalf("status=%d path=%q authorization=%q capability_headers=%v", recorder.Code, providerPath, providerAuthorization, providerCapabilityHeaders)
	}

	request = httptest.NewRequest(http.MethodPost, "/route/primary/__veil/"+capability+"/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("mixed path and header capabilities returned status %d", recorder.Code)
	}
}

func TestRouteCapabilityHeadersMustBeUnique(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"safe"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	for name, values := range map[string][]string{
		"duplicate session": {created.Session.ID, created.Session.ID},
		"duplicate token":   {created.Routes[0].Token, created.Routes[0].Token},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			if name == "duplicate session" {
				request.Header[HeaderSession] = values
			} else {
				request.Header[HeaderRouteToken] = values
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized || providerCalls != 0 {
				t.Fatalf("status=%d provider calls=%d", recorder.Code, providerCalls)
			}
		})
	}
}

func TestAuthorizedRequestsEmitSanitizedAuditPreview(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"ok"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, err := NewHandler(manager, []Route{{ID: "primary", AgentID: "agent-a", SurfaceID: "surface-a", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(auditor.events) != 1 {
		t.Fatalf("status=%d events=%+v", recorder.Code, auditor.events)
	}
	event := auditor.events[0]
	encoded, _ := json.Marshal(event)
	if event.AgentID != "agent-a" || event.SurfaceID != "surface-a" || event.SessionID != created.Session.ID || event.Protocol != domain.ProtocolOpenAIResponses || event.Action != domain.ActionRedact || event.FindingCount != 1 || len(event.FindingTypes) != 1 || event.FindingTypes[0] != "pii.email" || event.ErrorCode != "" || event.Preview != "***" || strings.Contains(string(encoded), "dev@example.com") {
		t.Fatalf("unsafe or incomplete event: %s", encoded)
	}
}

func TestBlockedRequestAuditRetainsDecisionMetadata(t *testing.T) {
	upstream, _ := url.Parse("https://api.example")
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionBlock}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, http.DefaultClient)
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || len(auditor.events) != 1 || auditor.events[0].Action != domain.ActionBlock || auditor.events[0].ErrorCode != domain.ErrPolicyBlocked || auditor.events[0].FindingCount != 1 {
		t.Fatalf("status=%d events=%+v", recorder.Code, auditor.events)
	}
}
func TestAuthenticationRunsAfterRedaction(t *testing.T) {
	signer := &finalBodySigner{}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Signed") != "yes" {
			t.Error("signature missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"ok"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Auth: domain.AuthStrategy{Type: domain.AuthCustom}, AuthApplier: veilauth.Applier{Signers: map[domain.AuthType]veilauth.Signer{domain.AuthCustom: signer}}, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if signer.sawOriginal || recorder.Code != http.StatusOK {
		t.Fatalf("original=%v status=%d", signer.sawOriginal, recorder.Code)
	}
}

func TestMissingRouteCapabilityIsRejectedBeforeForward(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	handler, _ := NewHandler(session.NewManager(), []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 10, MaxResponseBytes: 10, VaultLimits: redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 10}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || providerCalls != 0 {
		t.Fatalf("status=%d calls=%d", recorder.Code, providerCalls)
	}
}

func TestExternalOriginIsRejectedBeforeForward(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"safe"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Host = "127.0.0.1:43123"
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrInvalidOrigin)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
	for name, expected := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cross-Origin-Resource-Policy": "same-origin"} {
		if actual := recorder.Header().Get(name); actual != expected {
			t.Fatalf("%s=%q, want %q", name, actual, expected)
		}
	}

	request = httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Host = "127.0.0.1:43123"
	request.Header.Set("Origin", "http://127.0.0.1:43123")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerCalls != 1 {
		t.Fatalf("same-origin request status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func TestRouteProtocolCannotBeChangedByRequestPath(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolAnthropic, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func TestMalformedProtocolEnvelopeFailsBeforeUpstream(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func TestAmbiguousRequestRepresentationHeadersFailBeforeUpstream(t *testing.T) {
	for _, test := range []struct {
		name, header, first, second string
		code                        domain.ErrorCode
	}{
		{name: "content type", header: "Content-Type", first: "application/json", second: "text/plain", code: domain.ErrUnknownProtocol},
		{name: "content encoding", header: "Content-Encoding", first: "identity", second: "gzip", code: domain.ErrUnsupportedEncoding},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerCalls := 0
			provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(test.header, test.first)
			request.Header.Add(test.header, test.second)
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(test.code)) {
				t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
			}
		})
	}
}

func TestUnsupportedMethodFailsBeforeUpstream(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPut, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost || providerCalls != 0 || len(auditor.events) != 1 || auditor.events[0].ErrorCode != domain.ErrUnsupportedMethod {
		t.Fatalf("status=%d allow=%q calls=%d audit=%+v", recorder.Code, recorder.Header().Get("Allow"), providerCalls, auditor.events)
	}
}

func TestOpenAIModelsMetadataPassesThroughForCodexDiscovery(t *testing.T) {
	var providerMethod, providerPath, providerQuery string
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		providerMethod = request.Method
		providerPath = request.URL.Path
		providerQuery = request.URL.RawQuery
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Set-Cookie", "provider_state=discard; Secure; HttpOnly")
		_, _ = io.WriteString(writer, `{"data":[{"id":"model-a"}],"object":"list"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodGet, "/route/primary/v1/models?client_version=0.153.4", nil)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerMethod != http.MethodGet || providerPath != "/v1/models" || providerQuery != "client_version=0.153.4" || recorder.Header().Get("Set-Cookie") != "" || recorder.Body.String() != `{"data":[{"id":"model-a"}],"object":"list"}` {
		t.Fatalf("status=%d method=%q path=%q query=%q headers=%v body=%s", recorder.Code, providerMethod, providerPath, providerQuery, recorder.Header(), recorder.Body.String())
	}
}

func TestOpenAIModelsMetadataUsesRouteUpstreamBasePath(t *testing.T) {
	var providerPath string
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		providerPath = request.URL.Path
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"data":[],"object":"list"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL + "/backend-api/codex")
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodGet, "/route/primary/models", nil)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerPath != "/backend-api/codex/models" {
		t.Fatalf("status=%d path=%q body=%s", recorder.Code, providerPath, recorder.Body.String())
	}
}

func TestMCPStreamableGETPassesThroughResponseDLP(t *testing.T) {
	providerMethod := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMethod = r.Method
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":\"safe\"}}\n\n"))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, err := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/route/mcp/mcp", nil)
	setMCPAccept(request)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerMethod != http.MethodGet || !strings.Contains(recorder.Body.String(), `"value":"safe"`) {
		t.Fatalf("status=%d method=%q body=%s", recorder.Code, providerMethod, recorder.Body.String())
	}
}

func TestMCPStreamableRejectsUnsupportedVersionBeforeUpstream(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, err := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/mcp/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	setMCPAccept(request)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].Action != domain.ActionBlock || auditor.events[0].ErrorCode != domain.ErrUnknownProtocol {
		t.Fatalf("audit=%+v", auditor.events)
	}
}

func TestMCPStreamableRejectsBodyVersionMismatchBeforeUpstream(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/mcp/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	setMCPAccept(request)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func TestMCPStreamableForwardsImplementedVersion(t *testing.T) {
	providerVersion := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerVersion = r.Header.Get("MCP-Protocol-Version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/mcp/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	setMCPAccept(request)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerVersion != "2025-11-25" {
		t.Fatalf("status=%d provider version=%q body=%s", recorder.Code, providerVersion, recorder.Body.String())
	}
}

func TestMCPRoutesUseExactConfiguredUpstreamPath(t *testing.T) {
	for _, protocolType := range []domain.Protocol{domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable} {
		t.Run(string(protocolType), func(t *testing.T) {
			providerPath := ""
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			upstream.Path = "/custom/rpc"
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
			handler, err := NewHandler(manager, []Route{{ID: "mcp", Protocol: protocolType, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/route/mcp/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			if protocolType == domain.ProtocolMCPStreamable {
				setMCPAccept(request)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || providerPath != "/custom/rpc" {
				t.Fatalf("status=%d provider path=%q body=%s", recorder.Code, providerPath, recorder.Body.String())
			}
		})
	}
}

func TestMCPStreamableGETUsesConnectionLifetimeInsteadOfClientTimeout(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":\"safe\"}}\n\n"))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, &http.Client{Timeout: time.Millisecond})
	request := httptest.NewRequest(http.MethodGet, "/route/mcp/mcp", nil)
	setMCPAccept(request)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"value":"safe"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestMCPStreamableGETEndsAtProtectionSessionExpiry(t *testing.T) {
	providerCanceled := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(providerCanceled)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, 100*time.Millisecond)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, &http.Client{})
	request := httptest.NewRequest(http.MethodGet, "/route/mcp/mcp", nil)
	setMCPAccept(request)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	select {
	case <-providerCanceled:
	case <-time.After(time.Second):
		t.Fatal("provider request survived protection session expiry")
	}
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestActiveProtectedRequestEndsWhenSessionIsDeleted(t *testing.T) {
	providerStarted := make(chan struct{})
	providerCanceled := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		close(providerStarted)
		<-r.Context().Done()
		close(providerCanceled)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, &http.Client{})
	request := httptest.NewRequest(http.MethodGet, "/route/mcp/mcp", nil)
	setMCPAccept(request)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(requestDone)
	}()
	select {
	case <-providerStarted:
	case <-time.After(time.Second):
		t.Fatal("provider request did not start")
	}
	if !manager.Delete(created.Session.ID) {
		t.Fatal("session was not deleted")
	}
	select {
	case <-providerCanceled:
	case <-time.After(time.Second):
		t.Fatal("provider request survived explicit session deletion")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("proxy request survived explicit session deletion")
	}
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestASKFailsClosedWithoutSessionInteractionCapability(t *testing.T) {
	providerCalled := false
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalled = true
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	broker := policy.NewBroker()
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionAsk}, Interactive: true, Approver: broker, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"email dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalled || len(broker.Pending()) != 0 {
		t.Fatalf("status=%d provider-called=%t pending=%d body=%s", recorder.Code, providerCalled, len(broker.Pending()), recorder.Body.String())
	}
}

func TestPendingASKEndsWhenSessionIsDeletedBeforeUpstream(t *testing.T) {
	providerCalled := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		providerCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.CreateWithOptions("", "local", []string{"primary"}, time.Minute, session.CreateOptions{Interactive: true})
	broker := policy.NewBroker()
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionAsk}, Interactive: true, Approver: broker, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"email dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(requestDone)
	}()
	deadline := time.Now().Add(time.Second)
	for len(broker.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(broker.Pending()) != 1 {
		t.Fatal("request did not enter pending ASK state")
	}
	if !manager.Delete(created.Session.ID) {
		t.Fatal("session was not deleted")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("pending ASK survived explicit session deletion")
	}
	if recorder.Code != http.StatusForbidden || providerCalled || len(broker.Pending()) != 0 {
		t.Fatalf("status=%d provider-called=%t pending=%d body=%s", recorder.Code, providerCalled, len(broker.Pending()), recorder.Body.String())
	}
}

func TestPendingUploadEndsWhenSessionIsDeletedBeforeParsing(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("revoked upload reached provider")
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	body := &blockingRequestBody{started: make(chan struct{}), closed: make(chan struct{})}
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", nil)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(requestDone)
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("proxy did not start reading request body")
	}
	if !manager.Delete(created.Session.ID) {
		t.Fatal("session was not deleted")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request body read survived explicit session deletion")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestStreamingResponseClearsServerWriteDeadline(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"safe\"}\n\n"))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(recorder.deadlines) != 1 || !recorder.deadlines[0].IsZero() {
		t.Fatalf("status=%d deadlines=%v body=%s", recorder.Code, recorder.deadlines, recorder.Body.String())
	}
}

func TestMCPStreamableGETRejectsRequestBody(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodGet, "/route/mcp/mcp", strings.NewReader("unexpected"))
	setMCPAccept(request)
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func TestMCPStreamableNonPOSTCannotEscapeEndpoint(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL + "/gateway")
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	for _, path := range []string{"/route/mcp/mcp/../admin", "/route/mcp/mcp//admin", `/route/mcp/mcp\admin`} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set(HeaderSession, created.Session.ID)
		request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("path=%q status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
	if providerCalls != 0 {
		t.Fatalf("unsafe paths reached upstream: calls=%d", providerCalls)
	}
}

func TestMCPStreamableDELETEForwardsSessionAndEmptyResponse(t *testing.T) {
	providerMethod, providerSession := "", ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMethod = r.Method
		providerSession = r.Header.Get("Mcp-Session-Id")
		w.Header().Set("Mcp-Session-Id", providerSession)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodDelete, "/route/mcp/mcp", nil)
	request.Header.Set("Mcp-Session-Id", "mcp-session-1")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || providerMethod != http.MethodDelete || providerSession != "mcp-session-1" || recorder.Header().Get("Mcp-Session-Id") != "mcp-session-1" || recorder.Body.Len() != 0 {
		t.Fatalf("status=%d method=%q provider-session=%q response-session=%q body=%q", recorder.Code, providerMethod, providerSession, recorder.Header().Get("Mcp-Session-Id"), recorder.Body.String())
	}
}

func TestMCPStreamableRejectsIncompleteAcceptBeforeUpstream(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"mcp"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "mcp", Protocol: domain.ProtocolMCPStreamable, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/mcp/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
	}
}

func setMCPAccept(request *http.Request) {
	if request.Method == http.MethodPost {
		request.Header.Set("Accept", "application/json, text/event-stream")
	} else if request.Method == http.MethodGet {
		request.Header.Set("Accept", "text/event-stream")
	}
}

func TestProxyEvaluatesAgentProviderAndSurfacePolicyScope(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"route-primary"}, time.Minute)
	engine := policy.Engine{Default: domain.ActionAllow, Rules: []policy.Rule{{Scope: policy.Scope{AgentID: "agent-a", Provider: upstream.Hostname(), SurfaceID: "primary", FindingType: "pii.email"}, Action: domain.ActionBlock}}}
	handler, _ := NewHandler(manager, []Route{{ID: "route-primary", AgentID: "agent-a", SurfaceID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: engine, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/route-primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalls != 0 {
		t.Fatalf("status=%d calls=%d", recorder.Code, providerCalls)
	}
}

func TestStreamingResponseRestoresPlaceholder(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		var requestBody map[string]any
		_ = json.Unmarshal(payload, &requestBody)
		event, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": requestBody["input"]})
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		midpoint := len(event) / 2
		_, _ = w.Write([]byte("data: " + string(event[:midpoint])))
		w.(http.Flusher).Flush()
		_, _ = w.Write(append(event[midpoint:], []byte("\n\n")...))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 8192, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
	server := httptest.NewServer(handler)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/route/primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "dev@example.com") {
		t.Fatalf("stream did not restore placeholder: %s", body)
	}
}

func TestStreamingResponseFindingIsIncludedInAudit(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": "ghp_abcdefghijklmnopqrstuvwxyz"})
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: " + string(payload) + "\n\n"))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 8192, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "ghp_") || !strings.Contains(recorder.Body.String(), "[REDACTED]") || len(auditor.events) != 1 || auditor.events[0].FindingCount != 1 || auditor.events[0].Action != domain.ActionRedact || auditor.events[0].FindingTypes[0] != "secret.github_pat" {
		t.Fatalf("status=%d audit=%+v body=%s", recorder.Code, auditor.events, recorder.Body.String())
	}
}

func TestCompressedProviderResponsesFailClosedBeforeJSONOrSSEProcessing(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-stream"} {
		t.Run(contentType, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentType)
				w.Header().Set("Content-Encoding", "br")
				_, _ = w.Write([]byte("compressed-secret-shaped-bytes"))
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			auditor := &recordingAuditor{}
			handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 8192, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), string(domain.ErrUnsupportedEncoding)) || strings.Contains(recorder.Body.String(), "compressed-secret-shaped-bytes") {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if len(auditor.events) != 1 || auditor.events[0].ErrorCode != domain.ErrUnsupportedEncoding || auditor.events[0].Action != domain.ActionBlock {
				t.Fatalf("audit=%+v", auditor.events)
			}
		})
	}
}

func TestProviderResponseHeadersPassThroughWithinBounds(t *testing.T) {
	for name, headerValue := range map[string]string{
		"sensitive": "token=ghp_abcdefghijklmnopqrstuvwxyz",
		"oversized": strings.Repeat("x", maxResponseHeaderBytes),
	} {
		t.Run(name, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Debug-Token", headerValue)
				_, _ = io.WriteString(w, `{"output_text":"safe"}`)
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			auditor := &recordingAuditor{}
			handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if name == "sensitive" {
				if recorder.Code != http.StatusOK || recorder.Header().Get("X-Debug-Token") != headerValue || len(auditor.events) != 1 || auditor.events[0].FindingCount != 0 || auditor.events[0].Action != domain.ActionAllow {
					t.Fatalf("transport header was not passed through: status=%d header=%q audit=%+v body=%s", recorder.Code, recorder.Header().Get("X-Debug-Token"), auditor.events, recorder.Body.String())
				}
				return
			}
			if recorder.Code != http.StatusBadGateway || recorder.Header().Get("X-Debug-Token") != "" || len(auditor.events) != 1 || auditor.events[0].ErrorCode != domain.ErrInvalidContract {
				t.Fatalf("oversized response headers were accepted: status=%d header=%q audit=%+v body=%s", recorder.Code, recorder.Header().Get("X-Debug-Token"), auditor.events, recorder.Body.String())
			}
		})
	}
}

func TestProviderResponseHeaderDoesNotInterpretContentPlaceholders(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo-Context", "[[VEIL_EMAIL_0123456789ABCDEF]]")
		_, _ = io.WriteString(w, `{"output_text":"safe"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Echo-Context") != "[[VEIL_EMAIL_0123456789ABCDEF]]" || recorder.Body.String() != `{"output_text":"safe"}` {
		t.Fatalf("status=%d header=%q body=%s", recorder.Code, recorder.Header().Get("X-Echo-Context"), recorder.Body.String())
	}
}

func TestProviderResponseBodyFindingIsIncludedInAudit(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"ghp_abcdefghijklmnopqrstuvwxyz"}`)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "ghp_") || !strings.Contains(recorder.Body.String(), "[REDACTED]") || len(auditor.events) != 1 || auditor.events[0].FindingCount != 1 || auditor.events[0].Action != domain.ActionRedact || auditor.events[0].FindingTypes[0] != "secret.github_pat" {
		t.Fatalf("status=%d audit=%+v body=%s", recorder.Code, auditor.events, recorder.Body.String())
	}
}

func TestAmbiguousProviderRepresentationHeadersFailClosed(t *testing.T) {
	for _, test := range []struct {
		name, header, first, second string
		code                        domain.ErrorCode
	}{
		{name: "content type", header: "Content-Type", first: "application/json", second: "text/event-stream", code: domain.ErrUnknownProtocol},
		{name: "content encoding", header: "Content-Encoding", first: "identity", second: "br", code: domain.ErrUnsupportedEncoding},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(test.header, test.first)
				w.Header().Add(test.header, test.second)
				_, _ = w.Write([]byte(`{"output_text":"provider-secret"}`))
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), string(test.code)) || strings.Contains(recorder.Body.String(), "provider-secret") {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestProviderSSEContentTypeRequiresExactMediaType(t *testing.T) {
	providerSecret := "provider-secret"
	if canary := os.Getenv("VEIL_TEST_LEAK_CANARY"); canary != "" {
		providerSecret = canary
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-streaming")
		payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": providerSecret})
		_, _ = w.Write(append(append([]byte("data: "), payload...), '\n', '\n'))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) || strings.Contains(recorder.Body.String(), providerSecret) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestProtectedRouteForcesIdentityResponseEncoding(t *testing.T) {
	providerAcceptEncoding := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"safe"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Encoding", "gzip, br")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerAcceptEncoding != "identity" {
		t.Fatalf("status=%d upstream accept-encoding=%q body=%s", recorder.Code, providerAcceptEncoding, recorder.Body.String())
	}
}

func TestUnknownProviderResponseEnvelopeFailsClosed(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"future_output":"dev@example.com"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) || strings.Contains(recorder.Body.String(), "dev@example.com") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(auditor.events) != 1 || auditor.events[0].Action != domain.ActionBlock || auditor.events[0].ErrorCode != domain.ErrUnknownProtocol {
		t.Fatalf("audit=%+v", auditor.events)
	}
}

func TestCredentialShapedProviderResponseFollowsRedactPolicy(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	auditor := &recordingAuditor{}
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Auditor: auditor, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(auditor.events) != 1 || auditor.events[0].Action != domain.ActionRedact || auditor.events[0].ErrorCode != "" || strings.Contains(recorder.Body.String(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.Contains(recorder.Body.String(), "[REDACTED]") {
		t.Fatalf("status=%d audit=%+v body=%s", recorder.Code, auditor.events, recorder.Body.String())
	}
}

func TestStreamingResponseFlushesSafeEventsBeforeProviderCloses(t *testing.T) {
	providerReady := make(chan struct{})
	releaseProvider := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 7; i++ {
			event, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": strings.Repeat(string(rune('a'+i)), 99) + " "})
			_, _ = w.Write([]byte("data: " + string(event) + "\n\n"))
		}
		w.(http.Flusher).Flush()
		close(providerReady)
		<-releaseProvider
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 8192, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	server := httptest.NewServer(handler)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	responses := make(chan *http.Response, 1)
	errors := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			errors <- err
			return
		}
		responses <- response
	}()
	<-providerReady
	select {
	case err := <-errors:
		close(releaseProvider)
		t.Fatal(err)
	case response := <-responses:
		close(releaseProvider)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if !strings.Contains(string(body), strings.Repeat("a", 99)+" ") {
			t.Fatalf("safe prefix missing: %s", body)
		}
	case <-time.After(time.Second):
		close(releaseProvider)
		t.Fatal("proxy buffered the stream until provider completion")
	}
}

func TestRedirectCannotEscapeCurrentRoute(t *testing.T) {
	evilCalls := 0
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilCalls++ }))
	defer evil.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 1024, MaxResponseBytes: 1024, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if evilCalls != 0 || recorder.Code != http.StatusBadGateway {
		t.Fatalf("redirect escaped: calls=%d status=%d", evilCalls, recorder.Code)
	}
}

func TestRedirectCannotChangeProtectedEndpointOnSameOrigin(t *testing.T) {
	for name, location := range map[string]string{
		"path":  "/different",
		"query": "/v1/responses?mode=unsafe",
	} {
		t.Run(name, func(t *testing.T) {
			providerCalls := 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls++
				if providerCalls == 1 {
					http.Redirect(w, r, location, http.StatusTemporaryRedirect)
				}
			}))
			defer provider.Close()
			upstream, _ := url.Parse(provider.URL)
			manager := session.NewManager()
			created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
			handler, err := NewHandler(manager, []Route{{ID: "primary", Protocol: domain.ProtocolOpenAIResponses, Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 1024, MaxResponseBytes: 1024, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(HeaderSession, created.Session.ID)
			request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if providerCalls != 1 || recorder.Code != http.StatusBadGateway {
				t.Fatalf("redirect changed protected endpoint: calls=%d status=%d body=%s", providerCalls, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestJoinBasePathAvoidsDuplicateProtocolPrefix(t *testing.T) {
	for _, test := range []struct {
		base, endpoint, want string
	}{
		{"", "/v1/responses", "/v1/responses"},
		{"/gateway", "/v1/responses", "/gateway/v1/responses"},
		{"/gateway/v1", "/v1/responses", "/gateway/v1/responses"},
		{"/anthropic/", "/v1/messages", "/anthropic/v1/messages"},
	} {
		if got := joinBasePath(test.base, test.endpoint); got != test.want {
			t.Fatalf("joinBasePath(%q, %q)=%q want=%q", test.base, test.endpoint, got, test.want)
		}
	}
}

func TestProtectedTargetPathPreservesCodexEndpointSuffix(t *testing.T) {
	for _, test := range []struct {
		base, endpoint, want string
	}{
		{"/backend-api/codex", "/responses", "/backend-api/codex/responses"},
		{"/backend-api/codex", "/models", "/backend-api/codex/models"},
		{"/v1", "/responses", "/v1/responses"},
	} {
		if got := protectedTargetPath(domain.ProtocolOpenAIResponses, test.base, test.endpoint); got != test.want {
			t.Fatalf("protectedTargetPath(%q, %q)=%q want=%q", test.base, test.endpoint, got, test.want)
		}
	}
}

func TestSniffResponseContentTypeReplaysUnmodifiedBody(t *testing.T) {
	for _, test := range []struct {
		body, want string
	}{
		{`{"output_text":"ok"}`, "application/json"},
		{"data: {\"type\":\"response.completed\"}\n\n", "text/event-stream"},
		{"opaque", ""},
	} {
		response := &http.Response{Body: io.NopCloser(strings.NewReader(test.body))}
		got, err := sniffResponseContentType(response)
		if err != nil || got != test.want {
			t.Fatalf("sniffResponseContentType(%q)=%q error=%v want=%q", test.body, got, err, test.want)
		}
		replayed, err := io.ReadAll(response.Body)
		if err != nil || string(replayed) != test.body {
			t.Fatalf("replayed body=%q error=%v want=%q", replayed, err, test.body)
		}
	}
}
