package planner

import (
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestBuildNeverMarksIncompleteCapabilityProtected(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", GeneratedAt: time.Now(),
		Agent: domain.AgentInstance{ID: "codex-1", Kind: "codex"},
		Surfaces: []domain.EgressSurface{
			{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses,
				Upstream: &domain.Upstream{Scheme: "https", Host: "api.openai.com", Port: 443}, ConfigSource: "fixture", Rewritable: true},
			{ID: "browser", Name: "Browser", Type: domain.SurfaceBrowser, Protocol: domain.ProtocolMCPHTTP,
				Upstream: &domain.Upstream{Scheme: "https", Host: "browser.example", Port: 443}, ConfigSource: "fixture", Rewritable: false},
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

func TestBuildCreatesRouteOnlyForFullCapability(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "custom"},
		Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary,
			Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443},
			ConfigSource: "fixture", Rewritable: true}}}
	plan, err := Build(manifest, Options{DefaultPolicy: "default", Capabilities: map[domain.Protocol]Capability{
		domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || plan.Coverage[0].Status != domain.CoverageProtected {
		t.Fatalf("expected one protected route, got %+v", plan)
	}
}
