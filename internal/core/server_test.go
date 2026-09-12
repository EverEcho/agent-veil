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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
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
	for _, required := range []string{"/v1/call-tree", "renderCalls", "Active call tree", "surface.coverage", "/v1/policy", "savePolicy", "/v1/detect", "testRules", "input cleared", "/v1/discovery", "Installed agents", "Inspection preview", "inspectAgent", "Inspect surfaces", "unknown version"} {
		if !strings.Contains(recorder.Body.String(), required) {
			t.Fatalf("dashboard is missing %q", required)
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
	payload, _ := json.Marshal(createRequest{RouteIDs: []string{routeID}, TTLSeconds: int64(time.Minute / time.Second)})
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
	if len(created.Routes) != 1 || created.Routes[0].Token == "" {
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
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg)
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
	if got := tree[""][0].Surfaces[0]; got.AgentID != "native-agent" || got.SurfaceID != "primary" || got.Coverage != domain.CoverageProtected {
		t.Fatalf("root surface=%+v", got)
	}
	reg.Remove("native-agent")
	tree = load()
	if got := tree[""][0].Surfaces[0]; got.AgentID != "" || got.SurfaceID != "" || got.Coverage != domain.CoverageUnprotected {
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
	var findings []domain.Finding
	if err := json.Unmarshal(recorder.Body.Bytes(), &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Category != "pii.email" || findings[0].Location.Path != "/test-input" {
		t.Fatalf("findings=%+v", findings)
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
	var findings []domain.Finding
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &findings) != nil || len(findings) != 1 || findings[0].Detector != "rule_pack" {
		t.Fatalf("status=%d findings=%+v body=%s", recorder.Code, findings, recorder.Body.String())
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
	if strings.Contains(string(encoded), "api.example") || strings.Contains(string(encoded), "443") {
		t.Fatalf("egress audit retained target metadata: %s", encoded)
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
	created, _ := manager.Create("", s.Endpoint(), []string{routeID}, time.Minute)
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
