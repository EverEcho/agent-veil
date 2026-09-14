package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

type fixedDiscoverer []discovery.Detection

func (f fixedDiscoverer) DetectAll(context.Context) []discovery.Detection {
	return append([]discovery.Detection(nil), f...)
}

type fixedInspectableDiscoverer struct {
	manifest domain.AgentManifest
}

type semanticLoaderFunc func(*os.File, modelstore.Manifest) (detector.Semantic, error)

func (f semanticLoaderFunc) Load(file *os.File, manifest modelstore.Manifest) (detector.Semantic, error) {
	return f(file, manifest)
}

func (value literalSemantic) Detect(path, text string) ([]domain.Finding, error) {
	start := strings.Index(text, string(value))
	if start < 0 {
		return nil, nil
	}
	return []domain.Finding{{RuleID: "semantic.name", Category: "pii.name", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: path, Start: start, End: start + len(value)}, Confidence: 0.9, Detector: "semantic", SuggestedAction: domain.ActionRedact}}, nil
}

func (failingAuditor) Append(domain.AuditEvent) error { return errors.New("disk unavailable") }

func (f fixedInspectableDiscoverer) DetectAll(context.Context) []discovery.Detection {
	return []discovery.Detection{{Agent: f.manifest.Agent.Kind, Version: f.manifest.Agent.Version}}
}
func (f fixedInspectableDiscoverer) Inspect(context.Context, string) (domain.AgentManifest, error) {
	return f.manifest, nil
}

func TestDecodeManagementRejectsDuplicateKeys(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(`{"agent_id":"visible","agent_id":"hidden"}`))
	request.Header.Set("Content-Type", "application/json")
	var destination struct {
		AgentID string `json:"agent_id"`
	}
	if err := decodeManagement(request, &destination); err == nil {
		t.Fatal("management request with duplicate identity was accepted")
	}
}

func TestCoreIdentityPreflightIsUnauthenticatedAndInstanceScoped(t *testing.T) {
	first, err := New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(session.NewManager(), "abcdefghijklmnopqrstuvwxyzABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if first.InstanceID() == "" || first.InstanceID() == second.InstanceID() {
		t.Fatalf("Core instance identities are not unique: first=%q second=%q", first.InstanceID(), second.InstanceID())
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	request, err := http.NewRequest(http.MethodGet, first.Endpoint()+"/v1/identity", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(APIVersionHeader, APIVersion)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var identity map[string]string
	if response.StatusCode != http.StatusOK || response.Header.Get(APIVersionHeader) != APIVersion || json.NewDecoder(response.Body).Decode(&identity) != nil || identity["api_version"] != APIVersion || identity["instance_id"] != first.InstanceID() {
		t.Fatalf("identity status=%d headers=%v body=%v", response.StatusCode, response.Header, identity)
	}
}

func TestDecodeManagementRequiresUnambiguousJSONRepresentation(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType []string
		encoding    []string
	}{
		{name: "missing content type"},
		{name: "wrong content type", contentType: []string{"text/plain"}},
		{name: "malformed content type", contentType: []string{"application/json; malformed"}},
		{name: "duplicate content type", contentType: []string{"application/json", "application/json"}},
		{name: "compressed", contentType: []string{"application/json"}, encoding: []string{"gzip"}},
		{name: "duplicate encoding", contentType: []string{"application/json"}, encoding: []string{"identity", "identity"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(`{"value":"safe"}`))
			request.Header["Content-Type"] = test.contentType
			request.Header["Content-Encoding"] = test.encoding
			var destination struct {
				Value string `json:"value"`
			}
			if err := decodeManagement(request, &destination); err == nil {
				t.Fatal("ambiguous management representation accepted")
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(`{"value":"safe"}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Content-Encoding", "identity")
	var destination struct {
		Value string `json:"value"`
	}
	if err := decodeManagement(request, &destination); err != nil || destination.Value != "safe" {
		t.Fatalf("valid management representation rejected: value=%q error=%v", destination.Value, err)
	}
}

func assertLocalSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for name, expected := range map[string]string{
		"Cache-Control":                "no-store",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if actual := header.Get(name); actual != expected {
			t.Fatalf("%s=%q, want %q", name, actual, expected)
		}
	}
}

func TestManagementAPIRequiresTokenAndUsesLoopback(t *testing.T) {
	s, err := New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if _, err := ListenAddress(s.Endpoint()); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(s.Endpoint() + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/health", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("authorized health failed: %v", err)
	}
	if response.Header.Get(APIVersionHeader) != APIVersion {
		t.Fatalf("management API version header=%q", response.Header.Get(APIVersionHeader))
	}
	response.Body.Close()
	request, _ = http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/compatibility", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("compatibility API failed: %v", err)
	}
	var records []map[string]any
	if err := json.NewDecoder(response.Body).Decode(&records); err != nil || len(records) == 0 {
		t.Fatalf("compatibility records=%v err=%v", records, err)
	}
	response.Body.Close()
}

func TestCoreRejectsDuplicateStartWithoutLosingOriginalListener(t *testing.T) {
	s, err := New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	endpoint := s.Endpoint()
	if err := s.Start(); err == nil {
		t.Fatal("duplicate Core start was accepted")
	}
	if s.Endpoint() != endpoint {
		t.Fatalf("original endpoint changed: got=%q want=%q", s.Endpoint(), endpoint)
	}
	request, _ := http.NewRequest(http.MethodGet, endpoint+"/v1/health", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("original listener unavailable: response=%v error=%v", response, err)
	}
	response.Body.Close()

	concurrent, _ := New(session.NewManager(), "01234567890123456789012345678901")
	start := make(chan struct{})
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			results <- concurrent.Start()
		}()
	}
	close(start)
	succeeded := 0
	for index := 0; index < 2; index++ {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent starts=%d, want 1", succeeded)
	}
	if err := concurrent.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagementAuthenticationRejectsAmbiguousOrMalformedCredentials(t *testing.T) {
	const token = "01234567890123456789012345678901"
	for name, candidate := range map[string][]string{
		"missing":        nil,
		"duplicate":      {"Bearer " + token, "Bearer " + token},
		"wrong scheme":   {"Basic " + token},
		"missing scheme": {token},
		"extra space":    {"Bearer  " + token},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := New(session.NewManager(), token)
			request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
			request.Header["Authorization"] = candidate
			recorder := httptest.NewRecorder()
			s.auth(s.health)(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
	s, _ := New(session.NewManager(), token)
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	request.Header.Set("Authorization", "bearer "+token)
	recorder := httptest.NewRecorder()
	s.auth(s.health)(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("case-insensitive bearer scheme rejected: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestManagementAPIRejectsIncompatibleRequestedVersionBeforeHandler(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	for name, versions := range map[string][]string{
		"future":    {"v2"},
		"duplicate": {APIVersion, APIVersion},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			handler := s.auth(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodPost, "/v1/change", nil)
			request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
			for _, version := range versions {
				request.Header.Add(APIVersionHeader, version)
			}
			recorder := httptest.NewRecorder()
			handler(recorder, request)
			if recorder.Code != http.StatusUpgradeRequired || called {
				t.Fatalf("status=%d called=%t body=%s", recorder.Code, called, recorder.Body.String())
			}
			if recorder.Header().Get(APIVersionHeader) != APIVersion {
				t.Fatalf("response API version=%q", recorder.Header().Get(APIVersionHeader))
			}
		})
	}
}

func TestCoreRejectsUnsafeAdminTokens(t *testing.T) {
	for name, token := range map[string]string{
		"short":      strings.Repeat("x", minAdminTokenBytes-1),
		"space":      strings.Repeat("x", minAdminTokenBytes) + " ",
		"control":    strings.Repeat("x", minAdminTokenBytes) + "\n",
		"non-ascii":  strings.Repeat("x", minAdminTokenBytes) + "密",
		"over-limit": strings.Repeat("x", maxAdminTokenBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(session.NewManager(), token); err == nil {
				t.Fatal("unsafe admin token accepted")
			}
		})
	}
}

func TestCoreRejectsDNSRebindingAuthorityAndCrossOriginManagement(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())

	request, _ := http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/health", nil)
	request.Host = "attacker.example"
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("external authority status=%d", response.StatusCode)
	}
	response.Body.Close()

	request, _ = http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/health", nil)
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin management status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestNativeIntegrationLeaseRegistrationAndHeartbeatAPI(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg)
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "native", Kind: "native", Mode: domain.ModeNative}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true, Required: true}}}
	payload, _ := json.Marshal(map[string]any{"manifest": manifest, "ttl_seconds": 60})
	request := httptest.NewRequest(http.MethodPost, "/v1/agents/leases", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.registerLeasedAgent(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("registration status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var entry registry.Entry
	if err := json.Unmarshal(recorder.Body.Bytes(), &entry); err != nil || entry.Generation != 1 || entry.ExpiresAt.IsZero() {
		t.Fatalf("leased entry=%+v err=%v", entry, err)
	}
	created, err := manager.Create("", "local", []string{entry.Plan.Routes[0].ID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorization, ok := manager.AuthorizeRoute(created.Session.ID, entry.Plan.Routes[0].ID, created.Routes[0].Token)
	if !ok {
		t.Fatal("registered Route Session was not authorized")
	}
	heartbeat, _ := json.Marshal(map[string]any{"generation": entry.Generation, "ttl_seconds": 120})
	request = httptest.NewRequest(http.MethodPost, "/v1/agents/native/heartbeat", bytes.NewReader(heartbeat))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("id", "native")
	recorder = httptest.NewRecorder()
	s.heartbeatAgent(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/agents/native/heartbeat", bytes.NewReader([]byte(`{"generation":2,"ttl_seconds":120}`)))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("id", "native")
	recorder = httptest.NewRecorder()
	s.heartbeatAgent(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale heartbeat status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodDelete, "/v1/agents/native?generation=2", nil)
	request.SetPathValue("id", "native")
	recorder = httptest.NewRecorder()
	s.deleteAgent(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodDelete, "/v1/agents/native?generation=1", nil)
	request.SetPathValue("id", "native")
	recorder = httptest.NewRecorder()
	s.deleteAgent(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("current delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(manager.List()) != 0 {
		t.Fatal("removed Integration left a Route Session active")
	}
	select {
	case <-authorization.Context.Done():
	default:
		t.Fatal("removed Integration did not cancel an in-flight Route authorization")
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/agents/leases", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	s.registerLeasedAgent(recorder, request)
	var replacement registry.Entry
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &replacement) != nil || replacement.Generation != 2 {
		t.Fatalf("reincarnated entry=%+v status=%d body=%s", replacement, recorder.Code, recorder.Body.String())
	}
}

func TestCoreASKCanResolveOnceWithoutExposingOriginal(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var providerRequest map[string]any
		_ = json.Unmarshal(body, &providerRequest)
		providerResponse, _ := json.Marshal(map[string]any{"output_text": providerRequest["input"]})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(providerResponse)
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	reg := registry.New(planner.Options{DefaultPolicy: "ask", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, _ := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port)}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "test", Rewritable: true, Required: true}}})
	routeID := registered.Plan.Routes[0].ID
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg).WithPolicy(policy.Engine{Default: domain.ActionAsk})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.CreateWithOptions("", s.Endpoint(), []string{routeID}, time.Minute, session.CreateOptions{Interactive: true})
	result := make(chan *http.Response, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/route/"+routeID+"/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Veil-Session", created.Session.ID)
		request.Header.Set("X-Veil-Route-Token", created.Routes[0].Token)
		response, _ := http.DefaultClient.Do(request)
		result <- response
	}()
	var approval policy.Approval
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		request, _ := http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/approvals", nil)
		request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
		response, _ := http.DefaultClient.Do(request)
		var pending []policy.Approval
		_ = json.NewDecoder(response.Body).Decode(&pending)
		response.Body.Close()
		if len(pending) > 0 {
			approval = pending[0]
			break
		}
	}
	if approval.ID == "" || approval.Finding.Category != "pii.email" {
		t.Fatalf("approval=%+v", approval)
	}
	payload := bytes.NewBufferString(`{"action":"redact"}`)
	request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/v1/approvals/"+approval.ID, payload)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("resolve=%v status=%d", err, response.StatusCode)
	}
	final := <-result
	if final.StatusCode != http.StatusOK {
		t.Fatalf("request status=%d", final.StatusCode)
	}
}
