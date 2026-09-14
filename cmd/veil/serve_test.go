package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

func TestConfigureManagedManifestMonitorRegistersBlocksAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "managed", Kind: "native", Mode: domain.ModeManaged}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "first.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "managed-file", Rewritable: true, Required: true}}}
	writeJSONFile := func(value any) {
		content, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSONFile(manifest)
	integrationRegistry := registry.New(runtimeOptions())
	monitor, err := configureManagedManifestMonitor(context.Background(), integrationRegistry, path)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := integrationRegistry.Get("managed")
	if !ok || entry.State != registry.StateActive || entry.Generation != 1 {
		t.Fatalf("initial managed entry=%+v exists=%v", entry, ok)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"v1","schema_version":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, changed, err := monitor.Check(context.Background())
	if err == nil || !changed || entry.State != registry.StateBlocked || entry.Generation != 2 {
		t.Fatalf("broken managed config did not block: entry=%+v changed=%v err=%v", entry, changed, err)
	}
	manifest.Surfaces[0].Upstream.Host = "second.example"
	writeJSONFile(manifest)
	entry, changed, err = monitor.Check(context.Background())
	if err != nil || !changed || entry.State != registry.StateActive || entry.Generation != 3 {
		t.Fatalf("repaired managed config did not recover: entry=%+v changed=%v err=%v", entry, changed, err)
	}
}

func TestConfigureManagedManifestMonitorRequiresManagedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launch.json")
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "launch", Kind: "native", Mode: domain.ModeLaunch}, Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "managed-file", Rewritable: true, Required: true}}}
	content, _ := json.Marshal(manifest)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configureManagedManifestMonitor(context.Background(), registry.New(runtimeOptions()), path); err == nil {
		t.Fatal("launch manifest was accepted as a managed source")
	}
}

func TestServeClearsCrashedCoreStateBeforeLaterStartupFailure(t *testing.T) {
	configDirectory := useTestUserConfigDir(t)
	t.Setenv("VEIL_ADMIN_TOKEN", "invalid")
	path := filepath.Join(configDirectory, "agentveil", "core.json")
	launchRoot := filepath.Join(configDirectory, "agentveil", "launches")
	if err := integration.ResetHermesLaunchRoot(launchRoot); err != nil {
		t.Fatal(err)
	}
	staleLaunch := filepath.Join(launchRoot, "agentveil-hermes-crashed")
	if err := os.Mkdir(staleLaunch, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleLaunch, "config.yaml"), []byte("credential: stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	instanceID := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if err := instance.WriteState(path, instance.State{SchemaVersion: "v1", APIEndpoint: "http://127.0.0.1:4321", InstanceID: instanceID, ProcessID: 7, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := serve(); err == nil {
		t.Fatal("invalid startup configuration was accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("crashed Core state survived a new instance claim: %v", err)
	}
	if _, err := os.Lstat(staleLaunch); !os.IsNotExist(err) {
		t.Fatalf("crashed Hermes launch resources survived a new instance claim: %v", err)
	}
}

func TestConfigureRuleStoreRequiresCanonicalTrustKey(t *testing.T) {
	server, _ := core.New(session.NewManager(), "01234567890123456789012345678901")
	configDirectory := t.TempDir()
	if err := configureRuleStore(server, configDirectory, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := configureRuleStore(server, configDirectory, "invalid", ""); err == nil {
		t.Fatal("invalid rule trust key was accepted")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(public)
	if err := configureRuleStore(server, configDirectory, encoded, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(configDirectory, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("unsafe rule directory mode=%v", info.Mode())
	}
	if err := configureRuleStore(server, configDirectory, "", filepath.Join(configDirectory, "custom-rules")); err == nil {
		t.Fatal("rule path without trust key was accepted")
	}
}

func TestConfigureModelStoreRequiresCanonicalTrustKey(t *testing.T) {
	server, _ := core.New(session.NewManager(), "01234567890123456789012345678901")
	configDirectory := t.TempDir()
	if err := configureModelStore(server, configDirectory, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := configureModelStore(server, configDirectory, "invalid", ""); err == nil {
		t.Fatal("invalid model trust key was accepted")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(public)
	if err := configureModelStore(server, configDirectory, encoded, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(configDirectory, "models"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("unsafe model directory mode=%v", info.Mode())
	}
	if err := configureModelStore(server, configDirectory, "", filepath.Join(configDirectory, "custom-models")); err == nil {
		t.Fatal("model path without trust key was accepted")
	}
}
