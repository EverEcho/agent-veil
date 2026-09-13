package native

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

const testManagementToken = "01234567890123456789012345678901"

func TestNativeClientLeaseLifecycleAgainstCore(t *testing.T) {
	integrationRegistry := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	server, err := core.New(session.NewManager(), testManagementToken)
	if err != nil {
		t.Fatal(err)
	}
	server.WithRegistry(integrationRegistry)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	client, err := NewClient(server.Endpoint(), testManagementToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := nativeManifest()
	registered, err := client.Register(context.Background(), manifest, time.Minute)
	if err != nil || registered.State != "active" || registered.Generation != 1 || len(registered.Plan.Routes) != 1 {
		t.Fatalf("registration=%+v err=%v", registered, err)
	}
	renewed, err := client.Heartbeat(context.Background(), manifest.Agent.ID, registered.Generation, time.Minute)
	if err != nil || renewed.Generation != registered.Generation || !renewed.ExpiresAt.After(registered.ExpiresAt) {
		t.Fatalf("heartbeat=%+v err=%v", renewed, err)
	}
	if _, err := client.Heartbeat(context.Background(), manifest.Agent.ID, registered.Generation+1, time.Minute); err == nil {
		t.Fatal("stale generation heartbeat was accepted")
	}
	if err := client.Remove(context.Background(), manifest.Agent.ID, registered.Generation); err != nil {
		t.Fatal(err)
	}
	if _, ok := integrationRegistry.Get(manifest.Agent.ID); ok {
		t.Fatal("generation-bound removal left the Native registration active")
	}
}

func TestRouteClientCreatesScopedChildSession(t *testing.T) {
	integrationRegistry := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	registered, err := integrationRegistry.Reconcile(nativeManifest())
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager()
	server, _ := core.New(manager, testManagementToken)
	server.WithRegistry(integrationRegistry)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	parent, err := manager.Create("", server.Endpoint(), []string{registered.Plan.Routes[0].ID}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewRouteClient(server.Endpoint(), parent.Session.ID, parent.Routes[0].RouteID, parent.Routes[0].Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	child, err := client.CreateChild(context.Background(), time.Hour)
	if err != nil || child.Session.ParentSessionID != parent.Session.ID || child.Session.Interactive || child.Protocol != domain.ProtocolOpenAIChat || len(child.CapabilityTransports) != 1 || child.CapabilityTransports[0] != CapabilityTransportHeaders || len(child.Routes) != 1 || child.Routes[0].RouteID != parent.Routes[0].RouteID || child.Routes[0].Token == parent.Routes[0].Token {
		t.Fatalf("parent=%+v child=%+v err=%v", parent, child, err)
	}
	if !child.Session.ExpiresAt.Equal(parent.Session.ExpiresAt) {
		t.Fatalf("bounded child expiry=%s parent expiry=%s delta=%s", child.Session.ExpiresAt, parent.Session.ExpiresAt, child.Session.ExpiresAt.Sub(parent.Session.ExpiresAt))
	}
	childClient, err := NewRouteClient(server.Endpoint(), child.Session.ID, child.Routes[0].RouteID, child.Routes[0].Token, nil)
	if err != nil {
		t.Fatalf("child self-revocation failed: %v", err)
	}
	if err := childClient.Delete(context.Background()); err != nil {
		t.Fatalf("child self-revocation failed: %v", err)
	}
	if manager.Authorize(child.Session.ID, child.Routes[0].RouteID, child.Routes[0].Token) || !manager.Authorize(parent.Session.ID, parent.Routes[0].RouteID, parent.Routes[0].Token) {
		t.Fatal("child self-revocation retained the child or revoked its parent")
	}
	if err := client.Delete(context.Background()); err == nil {
		t.Fatal("root session self-revocation was accepted")
	}
}

func TestMaintainLeaseRenewsCleansUpAndDoesNotFightNewGeneration(t *testing.T) {
	integrationRegistry := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	server, _ := core.New(session.NewManager(), testManagementToken)
	server.WithRegistry(integrationRegistry)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	client, _ := NewClient(server.Endpoint(), testManagementToken, nil)
	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan Registration, 8)
	result := make(chan error, 1)
	manifest := nativeManifest()
	go func() {
		result <- client.MaintainLease(ctx, manifest, LeaseOptions{TTL: 2 * time.Second, HeartbeatInterval: 100 * time.Millisecond}, func(registration Registration) error {
			updates <- registration
			return nil
		})
	}()
	initial := <-updates
	renewed := <-updates
	if initial.Generation != 1 || renewed.Generation != initial.Generation || !renewed.ExpiresAt.After(initial.ExpiresAt) {
		t.Fatalf("initial=%+v renewed=%+v", initial, renewed)
	}
	replacement, err := integrationRegistry.ReconcileLeased(manifest, time.Minute)
	if err != nil || replacement.Generation != initial.Generation+1 {
		t.Fatalf("replacement=%+v err=%v", replacement, err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("superseded lease did not fail closed")
		}
	case <-time.After(time.Second):
		t.Fatal("superseded lease keeper did not stop")
	}
	cancel()
	retained, ok := integrationRegistry.Get(manifest.Agent.ID)
	if !ok || retained.Generation != replacement.Generation {
		t.Fatalf("lease cleanup removed a replacement generation: %+v ok=%v", retained, ok)
	}

	ctx, cancel = context.WithCancel(context.Background())
	result = make(chan error, 1)
	ready := make(chan struct{}, 1)
	go func() {
		result <- client.MaintainLease(ctx, manifest, LeaseOptions{TTL: 2 * time.Second, HeartbeatInterval: 100 * time.Millisecond}, func(Registration) error {
			select {
			case ready <- struct{}{}:
			default:
			}
			return nil
		})
	}()
	<-ready
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, ok := integrationRegistry.Get(manifest.Agent.ID); ok {
		t.Fatal("canceled lease keeper retained its generation")
	}
}

func TestNativeClientRejectsUnsafeAuthorityTokenAndMode(t *testing.T) {
	for _, endpoint := range []string{"https://127.0.0.1:1234", "http://localhost:1234", "http://192.0.2.1:1234", "http://127.0.0.1:1234/path", "http://user@127.0.0.1:1234"} {
		if _, err := NewClient(endpoint, testManagementToken, nil); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if _, err := NewClient("http://127.0.0.1:1234", "short", nil); err == nil {
		t.Fatal("unsafe management token was accepted")
	}
	if _, err := NewRouteClient("http://127.0.0.1:1234", "session-valid", "route-valid", "not-a-route-token", nil); err == nil {
		t.Fatal("unsafe route capability was accepted")
	}
	client, err := NewClient("http://127.0.0.1:1234", testManagementToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.MaintainLease(context.Background(), nativeManifest(), LeaseOptions{TTL: time.Second, HeartbeatInterval: time.Second}, func(Registration) error { return nil }); err == nil {
		t.Fatal("unsafe lease timing was accepted")
	}
	manifest := nativeManifest()
	manifest.Agent.Mode = domain.ModeLaunch
	if _, err := client.Register(context.Background(), manifest, time.Minute); err == nil {
		t.Fatal("launch manifest was accepted by Native SDK")
	}
}

func TestNativeClientRejectsRedirectsAndAmbiguousResponses(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("redirect target was reached")
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set(apiVersionHeader, apiVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"active","state":"blocked"}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testManagementToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.doJSON(context.Background(), http.MethodPost, "/redirect", map[string]string{"x": "y"}, http.StatusOK, &Registration{}); err == nil {
		t.Fatal("redirect was accepted")
	}
	if err := client.doJSON(context.Background(), http.MethodPost, "/ambiguous", map[string]string{"x": "y"}, http.StatusOK, &Registration{}); err == nil {
		t.Fatal("ambiguous JSON response was accepted")
	}
}

func TestRouteClientRejectsInvalidChildCapabilitySemantics(t *testing.T) {
	parentToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now().UTC()
		w.Header().Set(apiVersionHeader, apiVersion)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ChildSession{
			Session: ProtectionSession{ID: "session-child", ParentSessionID: "session-parent", CoreEndpoint: "http://127.0.0.1:1", StartedAt: now, ExpiresAt: now.Add(time.Minute), RouteIDs: []string{"route-primary"}},
			Routes:  []RouteCredential{{RouteID: "route-primary", Token: parentToken}}, Protocol: ProtocolOpenAIResponses, CapabilityTransports: []string{CapabilityTransportHeaders},
		})
	}))
	defer server.Close()
	client, err := NewRouteClient(server.URL, "session-parent", "route-primary", parentToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateChild(context.Background(), time.Minute); err == nil {
		t.Fatal("Core response that reused the parent token and mismatched its endpoint was accepted")
	}
}

func nativeManifest() AgentManifest {
	return AgentManifest{SchemaVersion: "v1", Agent: AgentInstance{ID: "native-sdk", Kind: "native", Version: "1.0.0", Mode: ModeNative}, Surfaces: []EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native-sdk", Rewritable: true, Required: true}}}
}
