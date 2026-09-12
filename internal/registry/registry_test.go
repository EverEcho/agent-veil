package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
)

type snapshotResult struct {
	revision string
	manifest domain.AgentManifest
	err      error
}

type sequenceSource struct {
	results []snapshotResult
	index   int
}

func (source *sequenceSource) Snapshot(context.Context) (string, domain.AgentManifest, error) {
	result := source.results[source.index]
	if source.index < len(source.results)-1 {
		source.index++
	}
	return result.revision, result.manifest, result.err
}

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

func TestManagedMonitorBlocksGapsDeduplicatesAndRecovers(t *testing.T) {
	options := planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}}
	registry := New(options)
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "openclaw", Kind: "openclaw", Mode: domain.ModeManaged}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: true, Required: true}}}
	source := &sequenceSource{results: []snapshotResult{
		{revision: "one", manifest: manifest},
		{revision: "one", manifest: manifest},
		{revision: "two", err: errors.New("invalid config")},
		{revision: "three", manifest: manifest},
	}}
	monitor, err := NewMonitor(registry, source, "openclaw", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	entry, changed, err := monitor.Check(context.Background())
	if err != nil || !changed || entry.State != StateActive || entry.Generation != 1 {
		t.Fatalf("initial state: entry=%+v changed=%v err=%v", entry, changed, err)
	}
	entry, changed, err = monitor.Check(context.Background())
	if err != nil || changed || entry.Generation != 1 {
		t.Fatalf("unchanged revision replanned: entry=%+v changed=%v err=%v", entry, changed, err)
	}
	entry, changed, err = monitor.Check(context.Background())
	if err == nil || !changed || entry.State != StateBlocked || entry.Generation != 2 {
		t.Fatalf("invalid revision did not block: entry=%+v changed=%v err=%v", entry, changed, err)
	}
	entry, changed, err = monitor.Check(context.Background())
	if err != nil || !changed || entry.State != StateActive || entry.Generation != 3 {
		t.Fatalf("valid revision did not recover: entry=%+v changed=%v err=%v", entry, changed, err)
	}
}

func TestManagedMonitorRejectsInvalidConstructionAndEmptyRevision(t *testing.T) {
	registry := New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}})
	if _, err := NewMonitor(registry, nil, "agent", time.Second); err == nil {
		t.Fatal("nil source was accepted")
	}
	source := &sequenceSource{results: []snapshotResult{{manifest: domain.AgentManifest{}}}}
	monitor, err := NewMonitor(registry, source, "agent", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	entry, changed, err := monitor.Check(context.Background())
	if err == nil || !changed || entry.State != StateBlocked || entry.Generation != 1 {
		t.Fatalf("empty revision did not block: entry=%+v changed=%v err=%v", entry, changed, err)
	}
}
