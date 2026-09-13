package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
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

type literalSemantic string

func (value literalSemantic) Detect(path, text string) ([]domain.Finding, error) {
	start := strings.Index(text, string(value))
	if start < 0 {
		return nil, nil
	}
	return []domain.Finding{{RuleID: "semantic.name", Category: "pii.name", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: path, Start: start, End: start + len(value)}, Confidence: 0.9, Detector: "semantic", SuggestedAction: domain.ActionRedact}}, nil
}

type failingAuditor struct{}

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

func TestHealthReportsAuditPersistenceFailures(t *testing.T) {
	s, err := New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	s.WithAuditor(failingAuditor{})
	if err := s.auditor.Append(domain.AuditEvent{}); err == nil {
		t.Fatal("failing auditor unexpectedly succeeded")
	}
	recorder := httptest.NewRecorder()
	s.health(recorder, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var health map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "degraded" || health["audit"] != "error" || health["audit_failures"] != "1" {
		t.Fatalf("health=%+v", health)
	}
}

func TestDashboardContainsNoProtectedData(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	s.dashboard(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "01234567890123456789012345678901") {
		t.Fatal("dashboard leaked management data")
	}
	assertLocalSecurityHeaders(t, recorder.Header())
	csp := recorder.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "base-uri 'none'") || !strings.Contains(csp, "form-action 'none'") {
		t.Fatalf("dashboard CSP=%q", csp)
	}
	noncePrefix := "script-src 'nonce-"
	nonceStart := strings.Index(csp, noncePrefix)
	if nonceStart < 0 {
		t.Fatalf("dashboard CSP has no script nonce: %q", csp)
	}
	nonceStart += len(noncePrefix)
	nonceEnd := strings.IndexByte(csp[nonceStart:], '\'')
	if nonceEnd < 0 {
		t.Fatalf("dashboard CSP has malformed nonce: %q", csp)
	}
	nonce := csp[nonceStart : nonceStart+nonceEnd]
	body := recorder.Body.String()
	if !strings.Contains(body, `<script nonce="`+nonce+`">`) || !strings.Contains(body, `<style nonce="`+nonce+`">`) || strings.Contains(body, " onclick=") || strings.Contains(body, " style=") {
		t.Fatal("dashboard contains untrusted inline execution or mismatched CSP nonces")
	}
	for _, required := range []string{"Local diagnostics", "downloadDiagnostics", "Export privacy-safe diagnostics", "final-payload privacy scans", "Today and 7-day risk trend", "renderTrends", "localDay", "Recent metadata trend", "Routing graph", "renderRoutes", "endpointText", "route.policy_id", "route.network", "renderRisks", "riskAction", "Risks and actions", "Impact:", "Action:", "/v1/call-tree", "renderCalls", "Active call tree", "surface.coverage", "/v1/policy", "savePolicy", "/v1/rules", "loadRulePacks", "activateRulePack", "deactivateRulePack", "removeRulePack", "remove-rule", "installRulePack", "Signed rule manifest JSON", "Verify and install", "Use built-in rules", "/v1/models", "loadModels", "activateModel", "deactivateModel", "removeModel", "remove-model", "installModel", "Signed model manifest JSON", "Verify and install model", "semantic inference remains unavailable", "/v1/detect", "testRules", "policyScope", "matched_scope", "ASK is shown as an interactive preview", "input cleared", "/v1/discovery", "Installed agents", "Inspection preview", "inspectAgent", "Inspect surfaces", "unknown version"} {
		if !strings.Contains(body, required) {
			t.Fatalf("dashboard is missing %q", required)
		}
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

func TestCoreBackgroundCleanupRevokesIdleExpiredSessions(t *testing.T) {
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.Create("", s.Endpoint(), []string{"primary"}, 25*time.Millisecond)
	authorization, ok := manager.AuthorizeRoute(created.Session.ID, "primary", created.Routes[0].Token)
	if !ok {
		t.Fatal("session authorization failed")
	}
	select {
	case <-authorization.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("idle expired session was not revoked by background cleanup")
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

func TestDiscoveryAPIUsesAuthenticatedInjectedInventory(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithDiscoverer(fixedDiscoverer{{Agent: "codex", Executable: "/bin/codex", Version: "1.2.3", Status: discovery.DetectionUnverified}})
	request := httptest.NewRequest(http.MethodGet, "/v1/discovery", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.getDiscovery)(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var detections []discovery.Detection
	if err := json.Unmarshal(recorder.Body.Bytes(), &detections); err != nil {
		t.Fatal(err)
	}
	if len(detections) != 1 || detections[0].Agent != "codex" || detections[0].Status != discovery.DetectionUnverified {
		t.Fatalf("detections=%+v", detections)
	}
}

func TestInspectionPreviewReturnsManifestAndTruthfulCoverage(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "openclaw", Kind: "openclaw", Version: "9.9.9", Mode: domain.ModeManaged, Metadata: map[string]string{"compatibility": "unverified"}}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: false, Required: true}}}
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {Observable: true}}})
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithRegistry(reg).WithDiscoverer(fixedInspectableDiscoverer{manifest: manifest})
	request := httptest.NewRequest(http.MethodGet, "/v1/discovery/openclaw", nil)
	request.SetPathValue("id", "openclaw")
	recorder := httptest.NewRecorder()
	s.getInspection(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Manifest domain.AgentManifest  `json:"manifest"`
		Plan     domain.ProtectionPlan `json:"protection_plan"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Agent.Metadata["compatibility"] != "unverified" || result.Plan.Summary.Observed != 1 || result.Plan.Summary.Protected != 0 || len(reg.List()) != 0 {
		t.Fatalf("preview mutated registry or overstated coverage: %+v", result)
	}
}

func TestSessionLifecycleAPI(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "test", Rewritable: true, Required: true}}}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithRegistry(reg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	registrationPayload, _ := json.Marshal(manifest)
	request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/v1/agents", bytes.NewReader(registrationPayload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("registration failed: %v status %d", err, response.StatusCode)
	}
	var registered registry.Entry
	if err := json.NewDecoder(response.Body).Decode(&registered); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	routeID := registered.Plan.Routes[0].ID
	if !strings.HasPrefix(routeID, "route-") || !strings.HasSuffix(routeID, "-g1") || len(routeID) != len("route-")+32+len("-g1") {
		t.Fatalf("route was not generation bound: %q", routeID)
	}
	payload, _ := json.Marshal(createRequest{RouteIDs: []string{routeID}, TTLSeconds: int64(time.Minute / time.Second), Interactive: true})
	request, _ = http.NewRequest(http.MethodPost, s.Endpoint()+"/v1/sessions", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("create failed: %v status %d", err, response.StatusCode)
	}
	var created session.Created
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if len(created.Routes) != 1 || created.Routes[0].Token == "" || !created.Session.Interactive {
		t.Fatal("route capability missing")
	}
	request, _ = http.NewRequest(http.MethodDelete, s.Endpoint()+"/v1/sessions/"+created.Session.ID, nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete failed: %v", err)
	}
}

func TestSessionAPIRejectsUnboundedTTLAndRouteCounts(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	for _, input := range []createRequest{
		{RouteIDs: []string{"route"}, TTLSeconds: int64(session.DefaultMaxTTL/time.Second) + 1},
		{RouteIDs: make([]string, session.DefaultMaxRoutes+1), TTLSeconds: 60},
	} {
		payload, _ := json.Marshal(input)
		request := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		s.createSession(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("unbounded session request status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestNativeIntegrationLeaseRegistrationAndHeartbeatAPI(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
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
}

func TestCallTreeMapsNestedSessionsToCurrentCoverage(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "native-agent", Kind: "native"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	routeID := registered.Plan.Routes[0].ID
	manager := session.NewManager()
	parent, err := manager.Create("", "http://127.0.0.1:1", []string{routeID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	child, err := manager.Create(parent.Session.ID, "http://127.0.0.1:1", []string{routeID}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	auditStore, err := audit.NewStore(filepath.Join(t.TempDir(), "private", "audit.jsonl"), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditTime := time.Now().UTC()
	if err := auditStore.Append(domain.AuditEvent{Timestamp: auditTime, SessionID: child.Session.ID, AgentID: "native-agent", SurfaceID: "primary", Protocol: domain.ProtocolOpenAIChat, FindingCount: 2, FindingTypes: []string{"pii.email"}, Severity: domain.SeverityHigh, Action: domain.ActionRedact, LatencyMS: 3}); err != nil {
		t.Fatal(err)
	}
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg).WithAuditor(auditStore)
	load := func() map[string][]registry.CallNode {
		request := httptest.NewRequest(http.MethodGet, "/v1/call-tree", nil)
		request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
		recorder := httptest.NewRecorder()
		s.auth(s.getCallTree)(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var tree map[string][]registry.CallNode
		if err := json.Unmarshal(recorder.Body.Bytes(), &tree); err != nil {
			t.Fatal(err)
		}
		return tree
	}
	tree := load()
	if len(tree[""]) != 1 || tree[""][0].SessionID != parent.Session.ID || len(tree[parent.Session.ID]) != 1 || tree[parent.Session.ID][0].SessionID != child.Session.ID {
		t.Fatalf("tree=%+v", tree)
	}
	if got := tree[""][0].Surfaces[0]; got.AgentID != "native-agent" || got.SurfaceID != "primary" || got.Protocol != domain.ProtocolOpenAIChat || got.PolicyID != "default" || got.Coverage != domain.CoverageProtected {
		t.Fatalf("root surface=%+v", got)
	}
	childNode := tree[parent.Session.ID][0]
	if childNode.Interactive || !childNode.ExpiresAt.Equal(child.Session.ExpiresAt) || childNode.Audit == nil || childNode.Audit.EventCount != 1 || childNode.Audit.FindingCount != 2 || childNode.Audit.LastAction != domain.ActionRedact || !childNode.Audit.LastAt.Equal(auditTime) {
		t.Fatalf("child call metadata=%+v", childNode)
	}
	reg.Remove("native-agent")
	tree = load()
	if got := tree[""][0].Surfaces[0]; got.AgentID != "" || got.SurfaceID != "" || got.Protocol != "" || got.PolicyID != "" || got.Coverage != domain.CoverageUnprotected {
		t.Fatalf("removed route retained protected claim: %+v", got)
	}
}

func TestPolicyAPIAtomicallyUpdatesAndPersistsEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "policy.json")
	store, _ := policy.NewStore(path)
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithPolicyStore(store); err != nil {
		t.Fatal(err)
	}
	document := policy.Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: []policy.Rule{{Scope: policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"}, Action: domain.ActionBlock}}}
	payload, _ := json.Marshal(document)
	request := httptest.NewRequest(http.MethodPut, "/v1/policy", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.updatePolicy)(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	decision, err := s.policyEngine().Decide(policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"}, true)
	if err != nil || decision.Action != domain.ActionBlock {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	restarted, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := restarted.WithPolicyStore(store); err != nil {
		t.Fatal(err)
	}
	decision, _ = restarted.policyEngine().Decide(policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"}, true)
	if decision.Action != domain.ActionBlock {
		t.Fatalf("persisted decision=%+v", decision)
	}
}

func TestDetectionTestAPIReportsMetadataWithoutEchoingOriginal(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	request := httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"contact dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "dev@example.com") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response detectionTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 || response.Results[0].Finding.Category != "pii.email" || response.Results[0].Finding.Location.Path != "/test-input" {
		t.Fatalf("response=%+v", response)
	}
	if decision := response.Results[0].Decision; decision.Action != domain.ActionRedact || decision.Source != "default" || decision.MatchedScope != nil || decision.Reason != "default policy" {
		t.Fatalf("decision=%+v", decision)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"safe","unexpected":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder = httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", recorder.Code)
	}
}

func TestDetectionTestAPIPreviewsMostSpecificPolicyWithoutEchoingInput(t *testing.T) {
	engine := policy.Engine{Default: domain.ActionAllow, Rules: []policy.Rule{{
		Scope:  policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"},
		Action: domain.ActionAsk,
	}}}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithPolicy(engine)
	request := httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"contact private@example.com","scope":{"agent_id":"agent-a","provider":"api.example","surface_id":"primary"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "private@example.com") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response detectionTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 {
		t.Fatalf("response=%+v", response)
	}
	decision := response.Results[0].Decision
	if decision.Action != domain.ActionAsk || decision.Source != "rule" || decision.Reason != "most specific matching rule" || decision.MatchedScope == nil || decision.MatchedScope.FindingType != "pii.email" {
		t.Fatalf("decision=%+v", decision)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"safe","scope":{"workspace":"/raw/path"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder = httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_DETECTION_SCOPE") {
		t.Fatalf("invalid scope status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRuleStoreActivePackConfiguresCoreDataPlane(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	sum := sha256.Sum256(payload)
	manifest := rulestore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
	if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"reference TICKET-123456"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	var response detectionTestResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil || len(response.Results) != 1 || response.Results[0].Finding.Detector != "rule_pack" {
		t.Fatalf("status=%d response=%+v body=%s", recorder.Code, response, recorder.Body.String())
	}
}

func TestRulePackManagementHotSwapsAndDeactivatesScanner(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	sum := sha256.Sum256(payload)
	manifest := rulestore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
	if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.semantic = literalSemantic("Alice")
	s.semanticRequired = true
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}

	inventoryRecorder := httptest.NewRecorder()
	s.listRulePacks(inventoryRecorder, httptest.NewRequest(http.MethodGet, "/v1/rules", nil))
	var inventory rulePackInventory
	if inventoryRecorder.Code != http.StatusOK || json.Unmarshal(inventoryRecorder.Body.Bytes(), &inventory) != nil || inventory.Active != "" || len(inventory.Versions) != 1 {
		t.Fatalf("inventory status=%d value=%+v body=%s", inventoryRecorder.Code, inventory, inventoryRecorder.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPut, "/v1/rules/active", strings.NewReader(`{"version":"1.0.0"}`))
	activate.Header.Set("Content-Type", "application/json")
	activateRecorder := httptest.NewRecorder()
	s.activateRulePack(activateRecorder, activate)
	if activateRecorder.Code != http.StatusNoContent {
		t.Fatalf("activation status=%d body=%s", activateRecorder.Code, activateRecorder.Body.String())
	}
	findings, err := s.currentScanner().ScanChecked("/input", "reference TICKET-123456")
	if err != nil || len(findings) != 1 || findings[0].Finding.Detector != "rule_pack" {
		t.Fatalf("active findings=%+v error=%v", findings, err)
	}
	semanticFindings, err := s.currentScanner().ScanChecked("/input", "Alice")
	if err != nil || len(semanticFindings) != 1 || semanticFindings[0].Finding.Detector != "semantic" {
		t.Fatalf("rule activation lost semantic detector: findings=%+v error=%v", semanticFindings, err)
	}

	deactivateRecorder := httptest.NewRecorder()
	s.deactivateRulePack(deactivateRecorder, httptest.NewRequest(http.MethodDelete, "/v1/rules/active", nil))
	if deactivateRecorder.Code != http.StatusNoContent {
		t.Fatalf("deactivation status=%d body=%s", deactivateRecorder.Code, deactivateRecorder.Body.String())
	}
	findings, err = s.currentScanner().ScanChecked("/input", "reference TICKET-123456")
	if err != nil || len(findings) != 0 {
		t.Fatalf("built-in findings=%+v error=%v", findings, err)
	}
	semanticFindings, err = s.currentScanner().ScanChecked("/input", "Alice")
	if err != nil || len(semanticFindings) != 1 || semanticFindings[0].Finding.Detector != "semantic" {
		t.Fatalf("rule deactivation lost semantic detector: findings=%+v error=%v", semanticFindings, err)
	}
	if _, _, err := store.OpenActive(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rule store remained active: %v", err)
	}
}

func TestRulePackManagementRemovesOnlyInactiveVersions(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	for _, version := range []string{"1.0.0", "1.1.0"} {
		sum := sha256.Sum256(payload)
		manifest := rulestore.Manifest{SchemaVersion: "v1", Version: version, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
		manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
		if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Activate("1.1.0"); err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}

	activeRequest := httptest.NewRequest(http.MethodDelete, "/v1/rules/1.1.0", nil)
	activeRequest.SetPathValue("version", "1.1.0")
	activeRecorder := httptest.NewRecorder()
	s.removeRulePack(activeRecorder, activeRequest)
	if activeRecorder.Code != http.StatusConflict {
		t.Fatalf("active removal status=%d body=%s", activeRecorder.Code, activeRecorder.Body.String())
	}

	inactiveRequest := httptest.NewRequest(http.MethodDelete, "/v1/rules/1.0.0", nil)
	inactiveRequest.SetPathValue("version", "1.0.0")
	inactiveRecorder := httptest.NewRecorder()
	s.removeRulePack(inactiveRecorder, inactiveRequest)
	if inactiveRecorder.Code != http.StatusNoContent {
		t.Fatalf("inactive removal status=%d body=%s", inactiveRecorder.Code, inactiveRecorder.Body.String())
	}
	versions, err := store.List()
	if err != nil || len(versions) != 1 || versions[0].Version != "1.1.0" {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}
}

func TestRulePackManagementInstallsOnlyCanonicalSignedArtifacts(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	sum := sha256.Sum256(payload)
	manifest := rulestore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
	requestPayload, _ := json.Marshal(rulePackInstall{Manifest: manifest, ArtifactBase64: base64.StdEncoding.EncodeToString(payload)})
	request := httptest.NewRequest(http.MethodPost, "/v1/rules", bytes.NewReader(requestPayload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.installRulePack(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("installation status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	versions, err := store.List()
	if err != nil || len(versions) != 1 || versions[0].Version != "1.0.0" {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}

	for name, mutate := range map[string]func(*rulePackInstall){
		"noncanonical base64": func(value *rulePackInstall) { value.ArtifactBase64 += "\n" },
		"bad signature": func(value *rulePackInstall) {
			value.Manifest.Version = "2.0.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := rulePackInstall{Manifest: manifest, ArtifactBase64: base64.StdEncoding.EncodeToString(payload)}
			mutate(&candidate)
			body, _ := json.Marshal(candidate)
			request := httptest.NewRequest(http.MethodPost, "/v1/rules", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			s.installRulePack(recorder, request)
			if recorder.Code == http.StatusCreated {
				t.Fatal("unsafe rule artifact was installed")
			}
		})
	}
}

func TestModelManagementStreamsSignedArtifactsAndManagesLifecycle(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := modelstore.New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithModelStore(store); err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified-onnx-model")
	sum := sha256.Sum256(payload)
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, modelstore.SigningPayload(manifest)))
	manifestJSON, _ := json.Marshal(manifest)
	upload := httptest.NewRequest(http.MethodPost, "/v1/models", bytes.NewReader(payload))
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set(ModelManifestHeader, base64.StdEncoding.EncodeToString(manifestJSON))
	uploadRecorder := httptest.NewRecorder()
	s.installModel(uploadRecorder, upload)
	if uploadRecorder.Code != http.StatusCreated {
		t.Fatalf("installation status=%d body=%s", uploadRecorder.Code, uploadRecorder.Body.String())
	}

	inventoryRecorder := httptest.NewRecorder()
	s.listModels(inventoryRecorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	var inventory modelInventory
	if inventoryRecorder.Code != http.StatusOK || json.Unmarshal(inventoryRecorder.Body.Bytes(), &inventory) != nil || inventory.Active != "" || len(inventory.Versions) != 1 || inventory.Versions[0].Version != manifest.Version {
		t.Fatalf("inventory status=%d value=%+v body=%s", inventoryRecorder.Code, inventory, inventoryRecorder.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPut, "/v1/models/active", strings.NewReader(`{"version":"1.0.0"}`))
	activate.Header.Set("Content-Type", "application/json")
	activateRecorder := httptest.NewRecorder()
	s.activateModel(activateRecorder, activate)
	if activateRecorder.Code != http.StatusNoContent {
		t.Fatalf("activation status=%d body=%s", activateRecorder.Code, activateRecorder.Body.String())
	}
	activeRemoval := httptest.NewRequest(http.MethodDelete, "/v1/models/1.0.0", nil)
	activeRemoval.SetPathValue("version", "1.0.0")
	activeRemovalRecorder := httptest.NewRecorder()
	s.removeModel(activeRemovalRecorder, activeRemoval)
	if activeRemovalRecorder.Code != http.StatusConflict {
		t.Fatalf("active removal status=%d body=%s", activeRemovalRecorder.Code, activeRemovalRecorder.Body.String())
	}

	deactivateRecorder := httptest.NewRecorder()
	s.deactivateModel(deactivateRecorder, httptest.NewRequest(http.MethodDelete, "/v1/models/active", nil))
	if deactivateRecorder.Code != http.StatusNoContent {
		t.Fatalf("deactivation status=%d body=%s", deactivateRecorder.Code, deactivateRecorder.Body.String())
	}
	remove := httptest.NewRequest(http.MethodDelete, "/v1/models/1.0.0", nil)
	remove.SetPathValue("version", "1.0.0")
	removeRecorder := httptest.NewRecorder()
	s.removeModel(removeRecorder, remove)
	if removeRecorder.Code != http.StatusNoContent {
		t.Fatalf("removal status=%d body=%s", removeRecorder.Code, removeRecorder.Body.String())
	}
	if versions, err := store.List(); err != nil || len(versions) != 0 {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}
}

func TestModelUploadRequiresCanonicalBoundedRepresentation(t *testing.T) {
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: 4, SHA256: strings.Repeat("0", 64), Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	manifestJSON, _ := json.Marshal(manifest)
	encoded := base64.StdEncoding.EncodeToString(manifestJSON)
	for _, test := range []struct {
		name          string
		contentTypes  []string
		encodings     []string
		manifests     []string
		contentLength int64
	}{
		{name: "missing manifest", contentTypes: []string{"application/octet-stream"}, contentLength: 4},
		{name: "duplicate manifest", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded, encoded}, contentLength: 4},
		{name: "noncanonical manifest", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded + "\n"}, contentLength: 4},
		{name: "compressed", contentTypes: []string{"application/octet-stream"}, encodings: []string{"gzip"}, manifests: []string{encoded}, contentLength: 4},
		{name: "ambiguous content type", contentTypes: []string{"application/octet-stream", "application/octet-stream"}, manifests: []string{encoded}, contentLength: 4},
		{name: "unknown body length", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded}, contentLength: -1},
		{name: "wrong body length", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded}, contentLength: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/models", strings.NewReader("onnx"))
			request.Header["Content-Type"] = test.contentTypes
			request.Header["Content-Encoding"] = test.encodings
			request.Header[ModelManifestHeader] = test.manifests
			request.ContentLength = test.contentLength
			if _, err := decodeModelUpload(request); err == nil {
				t.Fatal("unsafe model upload representation was accepted")
			}
		})
	}
}

func TestSemanticRuntimeLoadsActiveModelAndPreservesScannerOnFailedSwitch(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := modelstore.New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "2.0.0"} {
		payload := []byte("onnx-" + version)
		sum := sha256.Sum256(payload)
		manifest := modelstore.Manifest{SchemaVersion: "v1", Version: version, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
		manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, modelstore.SigningPayload(manifest)))
		if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatal(err)
	}
	loader := semanticLoaderFunc(func(file *os.File, manifest modelstore.Manifest) (detector.Semantic, error) {
		payload, err := io.ReadAll(file)
		if err != nil || string(payload) != "onnx-"+manifest.Version {
			return nil, errors.New("invalid model artifact")
		}
		if manifest.Version == "2.0.0" {
			return nil, errors.New("runtime rejected model")
		}
		return literalSemantic("Alice"), nil
	})
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithModelStore(store); err != nil {
		t.Fatal(err)
	}
	if err := s.WithSemanticRuntime(loader, true); err != nil {
		t.Fatal(err)
	}
	matches, err := s.currentScanner().ScanChecked("/input", "hello Alice")
	if err != nil || len(matches) != 1 || matches[0].Finding.Detector != "semantic" {
		t.Fatalf("active semantic matches=%+v error=%v", matches, err)
	}
	inventoryRecorder := httptest.NewRecorder()
	s.listModels(inventoryRecorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	var inventory modelInventory
	if inventoryRecorder.Code != http.StatusOK || json.Unmarshal(inventoryRecorder.Body.Bytes(), &inventory) != nil || !inventory.Runtime.Connected || !inventory.Runtime.Required || !inventory.Runtime.Active {
		t.Fatalf("inventory status=%d value=%+v body=%s", inventoryRecorder.Code, inventory, inventoryRecorder.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPut, "/v1/models/active", strings.NewReader(`{"version":"2.0.0"}`))
	activate.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.activateModel(recorder, activate)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("failed switch status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	file, active, err := store.OpenActive()
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if active.Version != "1.0.0" {
		t.Fatalf("failed switch changed active model to %q", active.Version)
	}
	matches, err = s.currentScanner().ScanChecked("/input", "hello Alice")
	if err != nil || len(matches) != 1 || matches[0].Finding.Detector != "semantic" {
		t.Fatalf("failed switch replaced scanner: matches=%+v error=%v", matches, err)
	}
}

func TestRequiredSemanticRuntimeFailsClosedWithoutActiveModel(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	loader := semanticLoaderFunc(func(*os.File, modelstore.Manifest) (detector.Semantic, error) {
		return literalSemantic("Alice"), nil
	})
	if err := s.WithSemanticRuntime(loader, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.currentScanner().ScanChecked("/input", "ordinary text"); err == nil {
		t.Fatal("required semantic runtime silently allowed content without an active model")
	}
	recorder := httptest.NewRecorder()
	s.health(recorder, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var health map[string]string
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &health) != nil || health["status"] != "degraded" || health["semantic"] != "required_unavailable" {
		t.Fatalf("health=%+v status=%d body=%s", health, recorder.Code, recorder.Body.String())
	}
}

func TestCoreServesRegisteredProtectedRoute(t *testing.T) {
	var received string
	var authorization string
	var receivedPath string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		authorization = r.Header.Get("Authorization")
		receivedPath = r.URL.Path
		var providerRequest map[string]any
		_ = json.Unmarshal(body, &providerRequest)
		providerResponse, _ := json.Marshal(map[string]any{"output_text": providerRequest["input"]})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(providerResponse)
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	t.Setenv("VEIL_TEST_CORE_TOKEN", "provider-token")
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port), Path: "/gateway/v1"}, Auth: domain.AuthStrategy{Type: domain.AuthBearer, Source: "environment:VEIL_TEST_CORE_TOKEN"}, ConfigSource: "test", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	routeID := registered.Plan.Routes[0].ID
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	auditStore, _ := audit.NewStore(filepath.Join(t.TempDir(), "private", "audit.jsonl"), time.Hour, nil)
	s.WithRegistry(reg).WithAuditor(auditStore)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.Create("", s.Endpoint(), []string{routeID}, time.Minute)
	request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/route/"+routeID+"/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Veil-Session", created.Session.ID)
	request.Header.Set("X-Veil-Route-Token", created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || strings.Contains(received, "dev@example.com") || !strings.Contains(string(body), "dev@example.com") || authorization != "Bearer provider-token" || receivedPath != "/gateway/v1/responses" {
		t.Fatalf("status=%d provider=%s path=%q auth=%q body=%s", response.StatusCode, received, receivedPath, authorization, body)
	}
	auditRequest, _ := http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/audit", nil)
	auditRequest.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	auditResponse, err := http.DefaultClient.Do(auditRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer auditResponse.Body.Close()
	var events []domain.AuditEvent
	if err := json.NewDecoder(auditResponse.Body).Decode(&events); err != nil || len(events) != 1 || events[0].FindingCount != 1 || events[0].FindingTypes[0] != "pii.email" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestRouteCapabilityCreatesOnlySameRouteBoundedChildSession(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "native-parent", Kind: "native", Mode: domain.ModeNative}, Surfaces: []domain.EgressSurface{
		{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true, Required: true},
		{ID: "other", Name: "Other", Type: domain.SurfaceModelAuxiliary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "https", Host: "other.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true},
	}}
	registered, err := reg.Reconcile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager()
	server, _ := New(manager, "01234567890123456789012345678901")
	server.WithRegistry(reg)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	primaryRoute, otherRoute := registered.Plan.Routes[0].ID, registered.Plan.Routes[1].ID
	parent, err := manager.CreateWithOptions("", server.Endpoint(), []string{primaryRoute}, time.Minute, session.CreateOptions{Interactive: false})
	if err != nil {
		t.Fatal(err)
	}
	primaryToken := parent.Routes[0].Token
	requestChild := func(routeID string, ttl int64, configure func(http.Header)) *http.Response {
		payload, _ := json.Marshal(map[string]any{"ttl_seconds": ttl})
		request, _ := http.NewRequest(http.MethodPost, server.Endpoint()+"/v1/sessions/"+parent.Session.ID+"/routes/"+routeID+"/children", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(APIVersionHeader, APIVersion)
		request.Header.Set(veilproxy.HeaderSession, parent.Session.ID)
		request.Header.Set(veilproxy.HeaderRouteToken, primaryToken)
		if configure != nil {
			configure(request.Header)
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	response := requestChild(primaryRoute, 30, nil)
	var child session.Created
	if err := json.NewDecoder(response.Body).Decode(&child); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || child.Session.ParentSessionID != parent.Session.ID || child.Session.Interactive || len(child.Routes) != 1 || child.Routes[0].RouteID != primaryRoute || child.Routes[0].Token == primaryToken {
		t.Fatalf("status=%d child=%+v", response.StatusCode, child)
	}
	response = requestChild(otherRoute, 30, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-route child status=%d", response.StatusCode)
	}
	adminPayload, _ := json.Marshal(createRequest{ParentSessionID: parent.Session.ID, RouteIDs: []string{otherRoute}, TTLSeconds: 30})
	adminRequest := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewReader(adminPayload))
	adminRequest.Header.Set("Content-Type", "application/json")
	adminRecorder := httptest.NewRecorder()
	server.createSession(adminRecorder, adminRequest)
	if adminRecorder.Code != http.StatusBadRequest {
		t.Fatalf("management child route escalation status=%d body=%s", adminRecorder.Code, adminRecorder.Body.String())
	}
	response = requestChild(primaryRoute, 90, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("overlong child status=%d", response.StatusCode)
	}
	response = requestChild(primaryRoute, 30, func(header http.Header) {
		header[veilproxy.HeaderRouteToken] = []string{primaryToken, primaryToken}
	})
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("duplicate token child status=%d", response.StatusCode)
	}
	if !manager.Delete(parent.Session.ID) || manager.Authorize(child.Session.ID, primaryRoute, child.Routes[0].Token) {
		t.Fatal("parent deletion did not cascade to the child session")
	}
}

func TestRouteCapabilityTransportMatchesProxyInjectionMode(t *testing.T) {
	tests := []struct {
		kind string
		auth domain.AuthType
		want []string
	}{
		{kind: "native", auth: domain.AuthPassthrough, want: []string{capabilityTransportHeaders}},
		{kind: "claude", auth: domain.AuthAnthropicKey, want: []string{capabilityTransportAnthropicAPIKey}},
		{kind: "claude", auth: domain.AuthPassthrough, want: []string{capabilityTransportHeaders}},
		{kind: "hermes", auth: domain.AuthCustom, want: []string{capabilityTransportHeaders, capabilityTransportPath}},
	}
	for _, test := range tests {
		route := domain.ProtectedRoute{Auth: domain.AuthStrategy{Type: test.auth}}
		if got := routeCapabilityTransports(route, test.kind); !slices.Equal(got, test.want) {
			t.Fatalf("kind=%q auth=%q transports=%q want=%q", test.kind, test.auth, got, test.want)
		}
	}
}

func TestUnexpectedEgressReportIsBoundToLiveRouteAndPrivacySafe(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "agent", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "test", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	routeID := registered.Plan.Routes[0].ID
	manager := session.NewManager()
	created, err := manager.Create("", "http://127.0.0.1:1", []string{routeID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "private", "audit.jsonl"), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := New(manager, "01234567890123456789012345678901")
	server.WithRegistry(reg).WithAuditor(store)
	body := fmt.Sprintf(`{"session_id":%q,"agent_id":"agent","generation":%d,"route_id":%q,"transport":"udp"}`, created.Session.ID, registered.Generation, routeID)
	request := httptest.NewRequest(http.MethodPost, "/v1/egress-events", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.reportUnexpectedEgress(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	events, err := store.Recent(time.Now().UTC())
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	event := events[0]
	if event.SessionID != created.Session.ID || event.AgentID != "agent" || event.SurfaceID != "primary" || event.Protocol != domain.ProtocolOpenAIResponses || event.Action != domain.ActionBlock || event.ErrorCode != domain.ErrUnexpectedEgress || event.FindingCount != 1 || len(event.FindingTypes) != 1 || event.FindingTypes[0] != "network.unexpected_egress.udp" {
		t.Fatalf("event=%+v", event)
	}
	encoded, _ := json.Marshal(event)
	var eventDocument map[string]any
	if err := json.Unmarshal(encoded, &eventDocument); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"target", "host", "port", "upstream"} {
		if _, exists := eventDocument[field]; exists {
			t.Fatalf("egress audit retained target field %q: %s", field, encoded)
		}
	}
	diagnosticRecorder := httptest.NewRecorder()
	server.diagnostics(diagnosticRecorder, httptest.NewRequest(http.MethodGet, "/v1/diagnostics", nil))
	diagnosticPayload := diagnosticRecorder.Body.String()
	if diagnosticRecorder.Code != http.StatusOK || !strings.Contains(diagnosticRecorder.Header().Get("Content-Disposition"), "agentveil-diagnostics.json") {
		t.Fatalf("diagnostic status=%d headers=%v body=%s", diagnosticRecorder.Code, diagnosticRecorder.Header(), diagnosticPayload)
	}
	for _, forbidden := range []string{"api.example", created.Session.ID, "\"agent\""} {
		if strings.Contains(diagnosticPayload, forbidden) {
			t.Fatalf("diagnostic export leaked %q: %s", forbidden, diagnosticPayload)
		}
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/egress-events", strings.NewReader(strings.Replace(body, fmt.Sprintf(`"generation":%d`, registered.Generation), `"generation":999`, 1)))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.reportUnexpectedEgress(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("unbound report status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCoreProxyConcurrencyLimitDoesNotBlockManagement(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[]}`))
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port)}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "test", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	routeID := registered.Plan.Routes[0].ID
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg)
	if err := s.WithProxyConcurrency(1); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.Create("", s.Endpoint(), []string{routeID}, time.Minute)
	newProxyRequest := func() *http.Request {
		request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/route/"+routeID+"/v1/responses", strings.NewReader(`{"input":"ordinary"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Veil-Session", created.Session.ID)
		request.Header.Set("X-Veil-Route-Token", created.Routes[0].Token)
		return request
	}
	first := make(chan *http.Response, 1)
	go func() {
		response, _ := http.DefaultClient.Do(newProxyRequest())
		first <- response
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach provider")
	}

	second, err := http.DefaultClient.Do(newProxyRequest())
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || second.Header.Get("Retry-After") != "1" {
		t.Fatalf("over-limit status=%d retry-after=%q", second.StatusCode, second.Header.Get("Retry-After"))
	}
	management, _ := http.NewRequest(http.MethodGet, s.Endpoint()+"/v1/health", nil)
	management.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	health, err := http.DefaultClient.Do(management)
	if err != nil {
		t.Fatal(err)
	}
	if health.StatusCode != http.StatusOK {
		t.Fatalf("management request status=%d", health.StatusCode)
	}
	health.Body.Close()
	close(release)
	completed := <-first
	defer completed.Body.Close()
	if completed.StatusCode != http.StatusOK {
		t.Fatalf("first request status=%d", completed.StatusCode)
	}
}

func TestCoreRoutesMCPStreamableLifecycleMethods(t *testing.T) {
	var providerMethods []string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMethods = append(providerMethods, r.Method)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":\"safe\"}}\n\n"))
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolMCPStreamable: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "mcp-agent", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "remote-mcp", Name: "Remote MCP", Type: domain.SurfaceMCPHTTP, Protocol: domain.ProtocolMCPStreamable, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port)}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "test", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	routeID := registered.Plan.Routes[0].ID
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.Create("", s.Endpoint(), []string{routeID}, time.Minute)
	request := func(method string) *http.Request {
		result, _ := http.NewRequest(method, s.Endpoint()+"/route/"+routeID+"/mcp", nil)
		if method == http.MethodGet {
			result.Header.Set("Accept", "text/event-stream")
		}
		result.Header.Set("X-Veil-Session", created.Session.ID)
		result.Header.Set("X-Veil-Route-Token", created.Routes[0].Token)
		return result
	}
	response, err := http.DefaultClient.Do(request(http.MethodGet))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"value":"safe"`) {
		t.Fatalf("GET status=%d body=%s", response.StatusCode, body)
	}
	response, err = http.DefaultClient.Do(request(http.MethodDelete))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || len(providerMethods) != 2 || providerMethods[0] != http.MethodGet || providerMethods[1] != http.MethodDelete {
		t.Fatalf("DELETE status=%d provider methods=%v", response.StatusCode, providerMethods)
	}
}

func TestProxyConcurrencyConfigurationRejectsInvalidOrLateChanges(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithProxyConcurrency(0); err == nil {
		t.Fatal("zero concurrency limit accepted")
	}
	if err := s.WithProxyConcurrency(maxConcurrentProxyRequests + 1); err == nil {
		t.Fatal("unbounded concurrency limit accepted")
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if err := s.WithProxyConcurrency(1); err == nil {
		t.Fatal("late concurrency change accepted")
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
