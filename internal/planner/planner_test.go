package planner

import (
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/routing"
)

func TestBuildNeverMarksIncompleteCapabilityProtected(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", GeneratedAt: time.Now(),
		Agent: domain.AgentInstance{ID: "codex-1", Kind: "codex"},
		Surfaces: []domain.EgressSurface{
			{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses,
				Upstream: &domain.Upstream{Scheme: "https", Host: "api.openai.com", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true},
			{ID: "browser", Name: "Browser", Type: domain.SurfaceBrowser, Protocol: domain.ProtocolMCPHTTP,
				Upstream: &domain.Upstream{Scheme: "https", Host: "browser.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: false},
			{ID: "stdio", Name: "Local MCP", Type: domain.SurfaceMCPStdio, Protocol: domain.ProtocolLocalStdio, ConfigSource: "fixture"},
			{ID: "mystery", Name: "Mystery", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, ConfigSource: "fixture"},
		}}
	plan, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect},
		Capabilities: map[domain.Protocol]Capability{
			domain.ProtocolOpenAIResponses: {Protocol: domain.ProtocolOpenAIResponses, RequestInspection: true, ResponseInspection: true, StreamInspection: false},
			domain.ProtocolMCPHTTP:         {Protocol: domain.ProtocolMCPHTTP, Observable: true},
		}})
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.CoverageStatus{domain.CoveragePartial, domain.CoverageObserved, domain.CoverageLocal, domain.CoverageUnprotected}
	for i := range want {
		if plan.Coverage[i].Status != want[i] {
			t.Fatalf("coverage %d = %s, want %s", i, plan.Coverage[i].Status, want[i])
		}
	}
	if len(plan.Routes) != 0 || plan.Summary.Protected != 0 || plan.Summary.Total != 4 {
		t.Fatalf("invalid plan summary: %+v", plan)
	}
}

func TestBuildBlocksContentModifierAfterDLPWithoutDroppingRisk(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "custom"},
		Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary,
			Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443},
			Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true, Required: true}}}
	capabilities := map[domain.Protocol]Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}
	graph := routing.Graph{Nodes: []routing.Node{
		{ID: "agent", Name: "Agent", Kind: routing.NodeAgent},
		{ID: "veil", Name: "AgentVeil", Kind: routing.NodeDLP},
		{ID: "enhancer", Name: "Prompt enhancer", Kind: routing.NodeContentModifier},
		{ID: "provider", Name: "Provider", Kind: routing.NodeProvider},
	}}
	plan, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: capabilities, RoutingGraphs: map[string]routing.Graph{"primary": graph}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 0 || len(plan.Risks) != 1 || plan.Risks[0].Code != domain.RiskContentModifierAfterDLP || plan.Coverage[0].Status != domain.CoverageUnprotected || plan.Summary.Unprotected != 1 {
		t.Fatalf("unsafe graph plan=%+v", plan)
	}
}

func TestBuildAcceptsValidatedPreDLPModifierAndRejectsUnknownGraphSurface(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "custom"},
		Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary,
			Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443},
			Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true}}}
	capabilities := map[domain.Protocol]Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}
	graph := routing.Graph{Nodes: []routing.Node{
		{ID: "agent", Name: "Agent", Kind: routing.NodeAgent},
		{ID: "enhancer", Name: "Prompt enhancer", Kind: routing.NodeContentModifier},
		{ID: "veil", Name: "AgentVeil", Kind: routing.NodeDLP},
		{ID: "transport", Name: "Network", Kind: routing.NodeTransport},
		{ID: "provider", Name: "Provider", Kind: routing.NodeProvider},
	}}
	plan, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: capabilities, RoutingGraphs: map[string]routing.Graph{"primary": graph}})
	if err != nil || len(plan.Routes) != 1 {
		t.Fatalf("safe graph plan=%+v err=%v", plan, err)
	}
	if _, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: capabilities, RoutingGraphs: map[string]routing.Graph{"typo": graph}}); err == nil {
		t.Fatal("graph for unknown surface was ignored")
	}
	malformedAndUnsafe := routing.Graph{Nodes: []routing.Node{
		{ID: "agent", Name: "Agent", Kind: routing.NodeAgent},
		{ID: "veil", Name: "AgentVeil", Kind: routing.NodeDLP},
		{ID: "mystery", Name: "Mystery", Kind: routing.NodeKind("mystery")},
		{ID: "enhancer", Name: "Prompt enhancer", Kind: routing.NodeContentModifier},
		{ID: "provider", Name: "Provider", Kind: routing.NodeProvider},
	}}
	if _, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: capabilities, RoutingGraphs: map[string]routing.Graph{"primary": malformedAndUnsafe}}); err == nil {
		t.Fatal("malformed graph was downgraded to a routing risk")
	}
}

func TestBuildCreatesRouteOnlyForFullCapability(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "custom"},
		Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary,
			Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443},
			Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true}}}
	plan, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]Capability{
		domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || plan.Coverage[0].Status != domain.CoverageProtected {
		t.Fatalf("expected one protected route, got %+v", plan)
	}
}

func TestBuildRejectsInvalidNetworkAndRouteIDCollision(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "custom"}, Surfaces: []domain.EgressSurface{
		{ID: "model/a", Name: "One", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true},
		{ID: "model-a", Name: "Two", Type: domain.SurfaceModelFallback, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true},
	}}
	capabilities := map[domain.Protocol]Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}
	if _, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: capabilities}); err == nil {
		t.Fatal("colliding route ids were accepted")
	}
	manifest.Surfaces = manifest.Surfaces[:1]
	if _, err := Build(manifest, Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkHTTPProxy, Endpoint: "http://user:secret@127.0.0.1:8080"}, Capabilities: capabilities}); err == nil {
		t.Fatal("network route with embedded credentials was accepted")
	}
}
