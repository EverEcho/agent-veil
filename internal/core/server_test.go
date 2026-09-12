package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

func TestDashboardContainsNoProtectedData(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	s.dashboard(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "01234567890123456789012345678901") {
		t.Fatal("dashboard leaked management data")
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
}

func TestSessionLifecycleAPI(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	_, _ = reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, ConfigSource: "test", Rewritable: true, Required: true}}})
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithRegistry(reg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	payload, _ := json.Marshal(createRequest{RouteIDs: []string{"route-primary"}, TTLSeconds: int64(time.Minute / time.Second)})
	request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/v1/sessions", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response, err := http.DefaultClient.Do(request)
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

func TestCoreServesRegisteredProtectedRoute(t *testing.T) {
	var received string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	reg := registry.New(planner.Options{DefaultPolicy: "default", Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	_, err := reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port)}, ConfigSource: "test", Rewritable: true, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.Create("", s.Endpoint(), []string{"route-primary"}, time.Minute)
	request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/route/route-primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Veil-Session", created.Session.ID)
	request.Header.Set("X-Veil-Route-Token", created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || strings.Contains(received, "dev@example.com") || !strings.Contains(string(body), "dev@example.com") {
		t.Fatalf("status=%d provider=%s body=%s", response.StatusCode, received, body)
	}
}

func TestCoreASKCanResolveOnceWithoutExposingOriginal(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer provider.Close()
	parsed, _ := url.Parse(provider.URL)
	port, _ := strconv.Atoi(parsed.Port())
	reg := registry.New(planner.Options{DefaultPolicy: "ask", Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIResponses: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	_, _ = reg.Reconcile(domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "http", Host: parsed.Hostname(), Port: uint16(port)}, ConfigSource: "test", Rewritable: true, Required: true}}})
	manager := session.NewManager()
	s, _ := New(manager, "01234567890123456789012345678901")
	s.WithRegistry(reg).WithPolicy(policy.Engine{Default: domain.ActionAsk})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	created, _ := manager.Create("", s.Endpoint(), []string{"route-primary"}, time.Minute)
	result := make(chan *http.Response, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, s.Endpoint()+"/route/route-primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
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
