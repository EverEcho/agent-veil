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

func TestRegistrySnapshotsCannotMutateStoredProtectionState(t *testing.T) {
	options := planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}}
	registry := New(options)
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "native", Kind: "native", Metadata: map[string]string{"owner": "plugin"}}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Metadata: map[string]string{"model": "safe"}, Rewritable: true, Required: true}}}
	entry, err := registry.Reconcile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Agent.Metadata["owner"] = "mutated"
	manifest.Surfaces[0].Protocol = domain.ProtocolUnknown
	manifest.Surfaces[0].Upstream.Host = "attacker.example"
	manifest.Surfaces[0].Metadata["model"] = "mutated"
	entry.Manifest.Surfaces[0].Upstream.Host = "returned.example"
	entry.Plan.Coverage[0].Status = domain.CoverageUnprotected

	stored, ok := registry.Get("native")
	if !ok || stored.Manifest.Agent.Metadata["owner"] != "plugin" || stored.Manifest.Surfaces[0].Protocol != domain.ProtocolOpenAIChat || stored.Manifest.Surfaces[0].Upstream.Host != "api.example" || stored.Manifest.Surfaces[0].Metadata["model"] != "safe" || stored.Plan.Coverage[0].Status != domain.CoverageProtected {
		t.Fatalf("stored entry was mutated through a shared snapshot: %+v", stored)
	}
	listed := registry.List()
	listed[0].Manifest.Surfaces[0].Metadata["model"] = "list-mutated"
	stored, _ = registry.Get("native")
	if stored.Manifest.Surfaces[0].Metadata["model"] != "safe" {
		t.Fatalf("list result mutated registry: %+v", stored)
	}
}

func TestIntegrationLeaseExpiresAndRejectsStaleGeneration(t *testing.T) {
	options := planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}}
	registry := New(options)
	now := time.Now()
	registry.now = func() time.Time { return now }
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "native", Kind: "native", Mode: domain.ModeNative}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "native", Rewritable: true, Required: true}}}
	entry, err := registry.ReconcileLeased(manifest, time.Minute)
	if err != nil || entry.ExpiresAt != now.Add(time.Minute) {
		t.Fatalf("lease registration: entry=%+v err=%v", entry, err)
	}
	oldRouteID := entry.Plan.Routes[0].ID
	now = now.Add(30 * time.Second)
	entry, err = registry.Heartbeat("native", entry.Generation, time.Minute)
	if err != nil || entry.ExpiresAt != now.Add(time.Minute) || entry.Generation != 1 {
		t.Fatalf("lease heartbeat: entry=%+v err=%v", entry, err)
	}
	if _, err := registry.Heartbeat("native", entry.Generation+1, time.Minute); err == nil {
		t.Fatal("stale or unknown generation renewed lease")
	}
	now = now.Add(time.Minute)
	entry, ok := registry.Get("native")
	if !ok || entry.State != StateBlocked || entry.Generation != 2 || entry.ErrorCode != domain.ErrIntegrationExpired || len(entry.Plan.Routes) != 0 || !entry.ExpiresAt.IsZero() {
		t.Fatalf("expired lease retained active protection: %+v", entry)
	}
	if _, err := registry.Heartbeat("native", 1, time.Minute); err == nil {
		t.Fatal("expired generation renewed lease")
	}
	entry, err = registry.ReconcileLeased(manifest, time.Minute)
	if err != nil || entry.Generation != 3 || entry.Plan.Routes[0].ID == oldRouteID {
		t.Fatalf("new generation reused stale route capability: old=%q entry=%+v err=%v", oldRouteID, entry, err)
	}
	if registry.RemoveGeneration("native", 2) {
		t.Fatal("stale generation removed current registration")
	}
	if _, ok := registry.Get("native"); !ok || !registry.RemoveGeneration("native", entry.Generation) {
		t.Fatal("current generation could not be removed")
	}
}
