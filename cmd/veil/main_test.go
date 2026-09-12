package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
)

func TestInspectionIncludesManifestAndTruthfulPlan(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test"}, Surfaces: []domain.EgressSurface{{ID: "unknown", Name: "Unknown", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, ConfigSource: "test", Required: true}}}
	var output bytes.Buffer
	if err := writeInspection(&output, manifest); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Manifest domain.AgentManifest  `json:"manifest"`
		Plan     domain.ProtectionPlan `json:"protection_plan"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Agent.ID != "a" || result.Plan.Summary.Unprotected != 1 || result.Plan.Summary.Protected != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestProtectedCodexArgsKeepCapabilitiesOutOfArgv(t *testing.T) {
	args := protectedCodexArgs("http://127.0.0.1:1234/route/primary/v1", []string{"exec", "hello"}, true)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "session-secret") || !strings.Contains(joined, "env_http_headers") || !strings.Contains(joined, "env_key") {
		t.Fatalf("args=%v", args)
	}
}

func TestLaunchEnvironmentReplacesProviderCredentialWithoutDuplicates(t *testing.T) {
	environment := overlayEnvironment([]string{"PATH=/bin", "ANTHROPIC_API_KEY=real-provider-key"}, map[string]string{"ANTHROPIC_API_KEY": "veil-v1:session:route", "VEIL_SESSION_ID": "session"})
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "real-provider-key") || strings.Count(joined, "ANTHROPIC_API_KEY=") != 1 || !strings.Contains(joined, "ANTHROPIC_API_KEY=veil-v1:session:route") {
		t.Fatalf("environment=%v", environment)
	}
}

func TestResolveCoreEndpointUsesExplicitValueOrSecureState(t *testing.T) {
	if got, err := resolveCoreEndpoint("http://127.0.0.1:1234"); err != nil || got != "http://127.0.0.1:1234" {
		t.Fatalf("explicit endpoint=%q err=%v", got, err)
	}
	configDirectory := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDirectory)
	path := filepath.Join(configDirectory, "agentveil", "core.json")
	if err := instance.WriteState(path, instance.State{SchemaVersion: "v1", APIEndpoint: "http://127.0.0.1:4321", ProcessID: 7, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveCoreEndpoint(""); err != nil || got != "http://127.0.0.1:4321" {
		t.Fatalf("discovered endpoint=%q err=%v", got, err)
	}
}
