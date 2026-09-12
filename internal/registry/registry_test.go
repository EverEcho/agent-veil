package registry

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
)

func TestConfigChangeBlocksRequiredProtectionGap(t *testing.T) {
	options := planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}}
	registry := New(options)
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "agent", Kind: "native"}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true, Required: true}}}
	entry, err := registry.Reconcile(manifest)
	if err != nil || entry.State != StateActive {
		t.Fatalf("initial reconcile: %+v %v", entry, err)
	}
	manifest.Surfaces[0].Protocol = domain.ProtocolUnknown
	entry, err = registry.Reconcile(manifest)
	if err == nil || entry.State != StateBlocked || entry.Generation != 2 {
		t.Fatalf("gap was not blocked: %+v %v", entry, err)
	}
	stored, _ := registry.Get("agent")
	if stored.State != StateBlocked {
		t.Fatal("stale active claim remained")
	}
}

func TestNestedCallTree(t *testing.T) {
	tree, err := CallTree([]CallNode{{SessionID: "parent", Surfaces: []CallSurface{{RouteID: "route-acp", AgentID: "openclaw", SurfaceID: "acp", Coverage: domain.CoverageProtected}}}, {SessionID: "child", ParentSessionID: "parent", Surfaces: []CallSurface{{RouteID: "route-primary", AgentID: "codex", SurfaceID: "primary", Coverage: domain.CoverageProtected}}}})
	if err != nil || len(tree["parent"]) != 1 || tree["parent"][0].Surfaces[0].AgentID != "codex" {
		t.Fatalf("tree=%+v err=%v", tree, err)
	}
}

func TestNestedCallTreeRejectsCycles(t *testing.T) {
	_, err := CallTree([]CallNode{{SessionID: "a", ParentSessionID: "b", Surfaces: []CallSurface{{RouteID: "a", Coverage: domain.CoverageUnprotected}}}, {SessionID: "b", ParentSessionID: "a", Surfaces: []CallSurface{{RouteID: "b", Coverage: domain.CoverageUnprotected}}}})
	if err == nil {
		t.Fatal("cyclic session ancestry was accepted")
	}
}

func TestMalformedAnonymousManifestDoesNotPolluteRegistry(t *testing.T) {
	registry := New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}})
	if _, err := registry.Reconcile(domain.AgentManifest{SchemaVersion: "v1"}); err == nil {
		t.Fatal("malformed manifest was accepted")
	}
	if len(registry.List()) != 0 {
		t.Fatal("anonymous blocked entry polluted registry")
	}
}
