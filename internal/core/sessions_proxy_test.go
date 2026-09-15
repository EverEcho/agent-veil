package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

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

func TestExpiredIntegrationLeaseCancelsRouteSessions(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "native", Kind: "native", Mode: domain.ModeNative}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true, Required: true}}}
	entry, err := reg.ReconcileLeased(manifest, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager()
	created, err := manager.Create("", "http://127.0.0.1:8787", []string{entry.Plan.Routes[0].ID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorization, ok := manager.AuthorizeRoute(created.Session.ID, entry.Plan.Routes[0].ID, created.Routes[0].Token)
	if !ok {
		t.Fatal("route session authorization failed")
	}
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg)
	time.Sleep(time.Until(entry.ExpiresAt) + time.Millisecond)
	entries := s.registryEntries()
	if len(entries) != 1 || entries[0].State != registry.StateBlocked || len(manager.List()) != 0 {
		t.Fatalf("expired integration state=%+v sessions=%+v", entries, manager.List())
	}
	select {
	case <-authorization.Context.Done():
	default:
		t.Fatal("expired Integration did not cancel an in-flight Route authorization")
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
	if len(tree) != 0 || len(manager.List()) != 0 {
		t.Fatalf("removed route retained active call tree: tree=%+v sessions=%+v", tree, manager.List())
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
		{kind: "codex-desktop", auth: domain.AuthPassthrough, want: []string{capabilityTransportHeaders, capabilityTransportPath}},
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

func TestCoreKeepsLegacyMCPSSEStateAcrossPerRequestHandlers(t *testing.T) {
	providerMessage := make(chan string, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: endpoint\ndata: /messages?transport=legacy\n\n")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "event: message\ndata: "+<-providerMessage+"\n\n")
		case "/messages":
			if request.URL.RawQuery != "transport=legacy" {
				t.Errorf("dynamic endpoint query=%q", request.URL.RawQuery)
			}
			body, _ := io.ReadAll(request.Body)
			if !strings.Contains(string(body), `"method":"tools/list"`) {
				t.Errorf("legacy POST body=%s", body)
			}
			providerMessage <- `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, request)
		}
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	manager := session.NewManager()
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolMCPLegacySSE: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "hermes-legacy", Kind: "hermes", Version: "0.20.6"}, Surfaces: []domain.EgressSurface{{ID: "mcp-legacy", Name: "Legacy MCP", Type: domain.SurfaceMCPHTTP, Protocol: domain.ProtocolMCPLegacySSE, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port), Path: "/sse"}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "test", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(manager, "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	s.WithRegistry(reg)
	if err := s.WithProxyConcurrency(1); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	routeID := registered.Plan.Routes[0].ID
	created, err := manager.Create("", s.Endpoint(), []string{routeID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	streamRequest, _ := http.NewRequest(http.MethodGet, s.Endpoint()+"/route/"+routeID+"/mcp", nil)
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamRequest.Header.Set(veilproxy.HeaderSession, created.Session.ID)
	streamRequest.Header.Set(veilproxy.HeaderRouteToken, created.Routes[0].Token)
	streamResponse, err := http.DefaultClient.Do(streamRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer streamResponse.Body.Close()
	reader := bufio.NewReader(streamResponse.Body)
	dynamicEndpoint := ""
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.HasPrefix(line, "data: ") {
			dynamicEndpoint = strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		}
		if line == "\n" {
			break
		}
	}
	if !strings.HasPrefix(dynamicEndpoint, s.Endpoint()+"/route/"+routeID+"/__veil/") {
		t.Fatalf("dynamic endpoint=%q", dynamicEndpoint)
	}
	postRequest, _ := http.NewRequest(http.MethodPost, dynamicEndpoint, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	postRequest.Header.Set("Content-Type", "application/json")
	postResponse, err := http.DefaultClient.Do(postRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = postResponse.Body.Close()
	tail, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if streamResponse.StatusCode != http.StatusOK || postResponse.StatusCode != http.StatusAccepted || !strings.Contains(string(tail), `"tools":[]`) || s.legacySSE.Len() != 0 {
		t.Fatalf("stream=%d post=%d tail=%s channels=%d", streamResponse.StatusCode, postResponse.StatusCode, tail, s.legacySSE.Len())
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
