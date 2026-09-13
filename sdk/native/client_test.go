package native

import (
	"context"
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
	child, err := client.CreateChild(context.Background(), 30*time.Second)
	if err != nil || child.Session.ParentSessionID != parent.Session.ID || child.Session.Interactive || len(child.Routes) != 1 || child.Routes[0].RouteID != parent.Routes[0].RouteID || child.Routes[0].Token == parent.Routes[0].Token {
		t.Fatalf("child=%+v err=%v", child, err)
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

func nativeManifest() AgentManifest {
	return AgentManifest{SchemaVersion: "v1", Agent: AgentInstance{ID: "native-sdk", Kind: "native", Version: "1.0.0", Mode: ModeNative}, Surfaces: []EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native-sdk", Rewritable: true, Required: true}}}
}
