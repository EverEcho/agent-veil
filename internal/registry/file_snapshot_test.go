package registry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
)

func TestFileSnapshotSourceReturnsContentRevisionAndValidatedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	manifest := managedFileManifest("first.example")
	writeManagedManifest(t, path, manifest)
	source, err := NewFileSnapshotSource(path)
	if err != nil {
		t.Fatal(err)
	}
	firstRevision, first, err := source.Snapshot(context.Background())
	if err != nil || len(firstRevision) != 64 || first.Agent.ID != "managed" || first.Surfaces[0].Upstream.Host != "first.example" {
		t.Fatalf("revision=%q manifest=%+v err=%v", firstRevision, first, err)
	}
	secondRevision, _, err := source.Snapshot(context.Background())
	if err != nil || secondRevision != firstRevision {
		t.Fatalf("stable content revision changed: first=%q second=%q err=%v", firstRevision, secondRevision, err)
	}
	manifest.Surfaces[0].Upstream.Host = "second.example"
	writeManagedManifest(t, path, manifest)
	thirdRevision, third, err := source.Snapshot(context.Background())
	if err != nil || thirdRevision == firstRevision || third.Surfaces[0].Upstream.Host != "second.example" {
		t.Fatalf("changed content was not observed: revision=%q manifest=%+v err=%v", thirdRevision, third, err)
	}
}

func TestFileSnapshotSourceFailsClosedForUnsafeFilesAndJSON(t *testing.T) {
	root := t.TempDir()
	validPath := filepath.Join(root, "valid.json")
	writeManagedManifest(t, validPath, managedFileManifest("api.example"))
	linkedPath := filepath.Join(root, "linked.json")
	if err := os.Symlink(validPath, linkedPath); err != nil {
		t.Fatal(err)
	}
	invalidPath := filepath.Join(root, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"v1","schema_version":"v2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	unknownPath := filepath.Join(root, "unknown.json")
	content, _ := json.Marshal(managedFileManifest("api.example"))
	content = []byte(strings.TrimSuffix(string(content), "}") + `,"unexpected":true}`)
	if err := os.WriteFile(unknownPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(root, "oversized.json")
	if err := os.WriteFile(oversizedPath, make([]byte, MaxManagedManifestBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{linkedPath, invalidPath, unknownPath, oversizedPath}
	if runtime.GOOS != "windows" {
		writablePath := filepath.Join(root, "writable.json")
		writeManagedManifest(t, writablePath, managedFileManifest("api.example"))
		if err := os.Chmod(writablePath, 0o666); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, writablePath)
	}
	for _, path := range paths {
		source, err := NewFileSnapshotSource(path)
		if err != nil {
			t.Fatal(err)
		}
		if revision, manifest, err := source.Snapshot(context.Background()); err == nil || revision != "" || manifest.Agent.ID != "" {
			t.Fatalf("unsafe snapshot accepted for %s: revision=%q manifest=%+v err=%v", filepath.Base(path), revision, manifest, err)
		}
	}
}

func TestFileSnapshotSourceRejectsInvalidConstructionAndCancellation(t *testing.T) {
	if _, err := NewFileSnapshotSource("relative.json"); err == nil {
		t.Fatal("relative managed manifest path was accepted")
	}
	source, err := NewFileSnapshotSource(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := source.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot error=%v", err)
	}
}

func TestManagedFileMonitorBlocksBrokenRevisionAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	manifest := managedFileManifest("first.example")
	writeManagedManifest(t, path, manifest)
	source, err := NewFileSnapshotSource(path)
	if err != nil {
		t.Fatal(err)
	}
	registry := New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true}}})
	monitor, err := NewMonitor(registry, source, "managed", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	entry, changed, err := monitor.Check(context.Background())
	if err != nil || !changed || entry.State != StateActive || entry.Generation != 1 {
		t.Fatalf("initial managed file state: entry=%+v changed=%v err=%v", entry, changed, err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"v1","schema_version":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, changed, err = monitor.Check(context.Background())
	if err == nil || !changed || entry.State != StateBlocked || entry.Generation != 2 {
		t.Fatalf("broken managed file did not revoke protection: entry=%+v changed=%v err=%v", entry, changed, err)
	}
	manifest.Surfaces[0].Upstream.Host = "second.example"
	writeManagedManifest(t, path, manifest)
	entry, changed, err = monitor.Check(context.Background())
	if err != nil || !changed || entry.State != StateActive || entry.Generation != 3 || entry.Manifest.Surfaces[0].Upstream.Host != "second.example" {
		t.Fatalf("repaired managed file did not recover: entry=%+v changed=%v err=%v", entry, changed, err)
	}
}

func managedFileManifest(host string) domain.AgentManifest {
	return domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "managed", Kind: "native", Mode: domain.ModeManaged}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: host, Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "managed-file", Rewritable: true, Required: true}}}
}

func writeManagedManifest(t *testing.T, path string, manifest domain.AgentManifest) {
	t.Helper()
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
