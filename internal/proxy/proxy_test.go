package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/session"
)

func TestEndToEndProviderOnlyReceivesRedactedContent(t *testing.T) {
	var providerBody string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		providerBody = string(payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
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

func TestProxyChunkedScannerFindsEntityAcrossLongContextBoundary(t *testing.T) {
	var providerBody string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		providerBody = string(payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
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

type fixedCredentials map[string]string

func (c fixedCredentials) Resolve(source string) (string, error) { return c[source], nil }

func TestCapabilityCarrierIsRemovedBeforeProviderAuth(t *testing.T) {
	var providerKey string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func TestAuthorizedRequestsEmitMetadataOnlyAudit(t *testing.T) {
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
	if event.AgentID != "agent-a" || event.SurfaceID != "surface-a" || event.SessionID != created.Session.ID || event.Protocol != domain.ProtocolOpenAIResponses || event.Action != domain.ActionRedact || event.FindingCount != 1 || len(event.FindingTypes) != 1 || event.FindingTypes[0] != "pii.email" || event.ErrorCode != "" || strings.Contains(string(encoded), "dev@example.com") {
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

func TestMCPStreamableGETPassesThroughResponseDLP(t *testing.T) {
	providerMethod := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMethod = r.Method
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"result\":{\"value\":\"safe\"}}\n\n"))
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
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || providerMethod != http.MethodGet || !strings.Contains(recorder.Body.String(), `"value":"safe"`) {
		t.Fatalf("status=%d method=%q body=%s", recorder.Code, providerMethod, recorder.Body.String())
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
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || providerCalls != 0 || !strings.Contains(recorder.Body.String(), string(domain.ErrUnknownProtocol)) {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, providerCalls, recorder.Body.String())
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
			if len(auditor.events) != 1 || auditor.events[0].ErrorCode != domain.ErrUnsupportedEncoding {
				t.Fatalf("audit=%+v", auditor.events)
			}
		})
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
