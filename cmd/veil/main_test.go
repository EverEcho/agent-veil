package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/registry"
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

func TestLocalNoProxyPreservesExistingRulesAndAddsCoreAuthorities(t *testing.T) {
	value := localNoProxy("corp.example, localhost", ".internal,127.0.0.1")
	for _, required := range []string{"corp.example", ".internal", "127.0.0.1", "localhost", "::1"} {
		if strings.Count(strings.ToLower(value), strings.ToLower(required)) != 1 {
			t.Fatalf("NO_PROXY=%q missing or duplicated %q", value, required)
		}
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

func TestProtectedLaunchUsesCorePublishedGenerationRoute(t *testing.T) {
	entry := registry.Entry{State: registry.StateActive, Generation: 7, Plan: domain.ProtectionPlan{Routes: []domain.ProtectedRoute{{ID: "route-primary-g7"}}, Summary: domain.CoverageSummary{Total: 1, Protected: 1}}}
	route, err := singleProtectedRoute(entry)
	if err != nil || route.ID != "route-primary-g7" {
		t.Fatalf("route=%+v err=%v", route, err)
	}
	entry.State = registry.StateBlocked
	if _, err := singleProtectedRoute(entry); err == nil {
		t.Fatal("blocked Core registration was accepted for launch")
	}
}

func TestProtectedLaunchCancelsWhenLeaseHeartbeatFails(t *testing.T) {
	requests := 0
	requestPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		requestPath = r.URL.Path
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go maintainIntegrationLease(ctx, cancel, server.URL, "01234567890123456789012345678901", "codex-local", 7, time.Millisecond, time.Second, result)
	select {
	case err := <-result:
		if err == nil || requests != 1 || requestPath != "/v1/agents/codex-local/heartbeat" {
			t.Fatalf("err=%v requests=%d path=%q", err, requests, requestPath)
		}
		select {
		case <-ctx.Done():
		default:
			t.Fatal("failed heartbeat did not cancel protected child context")
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat failure did not return")
	}
}
