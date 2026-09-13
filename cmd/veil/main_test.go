package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
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

func TestProtectedRunInteractionFlagIsExplicitAndDoesNotConsumeChildFlag(t *testing.T) {
	name, child, interactive, err := parseProtectedRun([]string{"codex", "--interactive", "--", "exec", "task"})
	if err != nil || name != "codex" || !interactive || strings.Join(child, " ") != "exec task" {
		t.Fatalf("name=%q child=%v interactive=%t err=%v", name, child, interactive, err)
	}
	name, child, interactive, err = parseProtectedRun([]string{"codex", "--", "--interactive"})
	if err != nil || name != "codex" || interactive || len(child) != 1 || child[0] != "--interactive" {
		t.Fatalf("child flag was consumed: name=%q child=%v interactive=%t err=%v", name, child, interactive, err)
	}
	if _, _, _, err := parseProtectedRun(nil); err == nil {
		t.Fatal("missing protected run target was accepted")
	}
}

func TestHermesProtectedArgsRejectConfigurationBypasses(t *testing.T) {
	for _, args := range [][]string{{"--ignore-user-config"}, {"chat", "--safe-mode"}, {"--profile", "work"}, {"--profile=work"}, {"-p", "work"}} {
		if err := validateHermesProtectedArgs(args); err == nil {
			t.Fatalf("bypass args were accepted: %v", args)
		}
	}
	if err := validateHermesProtectedArgs([]string{"chat", "--ignore-rules", "-m", "gpt-5"}); err != nil {
		t.Fatalf("safe Hermes args were rejected: %v", err)
	}
}

func TestHermesManifestConfigPathRequiresOneAbsoluteConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	manifest := domain.AgentManifest{Surfaces: []domain.EgressSurface{{ID: "primary", ConfigSource: path}, {ID: "mcp-local", ConfigSource: path}}}
	if actual, err := hermesManifestConfigPath(manifest); err != nil || actual != path {
		t.Fatalf("path=%q err=%v", actual, err)
	}
	manifest.Surfaces[1].ConfigSource = filepath.Join(t.TempDir(), "config.yaml")
	if _, err := hermesManifestConfigPath(manifest); err == nil {
		t.Fatal("ambiguous Hermes configuration sources were accepted")
	}
	manifest.Surfaces = []domain.EgressSurface{{ID: "primary", ConfigSource: "relative/config.yaml"}}
	if _, err := hermesManifestConfigPath(manifest); err == nil {
		t.Fatal("relative Hermes configuration source was accepted")
	}
}

func TestReadProtectedHermesConfigRejectsLinksAndBoundsContent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	content := []byte("model: safe\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if actual, err := readProtectedHermesConfig(path); err != nil || string(actual) != string(content) {
		t.Fatalf("content=%q err=%v", actual, err)
	}
	link := filepath.Join(directory, "linked.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedHermesConfig(link); err == nil {
		t.Fatal("symlinked Hermes configuration was accepted")
	}
	empty := filepath.Join(directory, "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedHermesConfig(empty); err == nil {
		t.Fatal("empty Hermes configuration was accepted")
	}
}

func TestLaunchEnvironmentReplacesProviderCredentialWithoutDuplicates(t *testing.T) {
	environment := overlayEnvironment([]string{"PATH=/bin", "ANTHROPIC_API_KEY=real-provider-key", "anthropic_api_key=case-variant"}, map[string]string{"ANTHROPIC_API_KEY": "veil-v1:session:route", "VEIL_SESSION_ID": "session"})
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "real-provider-key") || strings.Count(joined, "ANTHROPIC_API_KEY=") != 1 || !strings.Contains(joined, "ANTHROPIC_API_KEY=veil-v1:session:route") {
		t.Fatalf("environment=%v", environment)
	}
}

func TestProtectedChildEnvironmentNeverInheritsCoreAdminToken(t *testing.T) {
	environment := protectedChildEnvironment(
		[]string{"PATH=/bin", "VEIL_ADMIN_TOKEN=management-secret", "veil_admin_token=case-variant", "VEIL_PARENT_SESSION=stale-parent", "veil_session_id=stale-session"},
		map[string]string{"VEIL_SESSION_ID": "session", "VEIL_ADMIN_TOKEN": "override-secret"},
	)
	joined := strings.Join(environment, "\n")
	if strings.Contains(strings.ToLower(joined), "veil_admin_token=") || strings.Contains(joined, "stale-parent") || strings.Contains(joined, "stale-session") || strings.Count(strings.ToLower(joined), "veil_session_id=") != 1 || !strings.Contains(joined, "VEIL_SESSION_ID=session") || !strings.Contains(joined, "PATH=/bin") {
		t.Fatalf("protected child environment=%v", environment)
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

func TestProtectedLaunchUsesCorePublishedGenerationRoute(t *testing.T) {
	entry := registry.Entry{State: registry.StateActive, Generation: 7, Plan: domain.ProtectionPlan{Routes: []domain.ProtectedRoute{{ID: "route-primary-g7", SurfaceID: "primary"}}, Summary: domain.CoverageSummary{Total: 1, Protected: 1}}}
	routes, err := fullyProtectedRoutes(entry)
	if err != nil || len(routes) != 1 || routes[0].ID != "route-primary-g7" {
		t.Fatalf("routes=%+v err=%v", routes, err)
	}
	entry.State = registry.StateBlocked
	if _, err := fullyProtectedRoutes(entry); err == nil {
		t.Fatal("blocked Core registration was accepted for launch")
	}
}

func TestProtectedLaunchBindsMultipleCredentialsByRouteID(t *testing.T) {
	routes := []domain.ProtectedRoute{{ID: "route-primary", SurfaceID: "primary"}, {ID: "route-fallback", SurfaceID: "fallback"}}
	entry := registry.Entry{State: registry.StateActive, Plan: domain.ProtectionPlan{Routes: routes, Summary: domain.CoverageSummary{Total: 3, Protected: 2, Local: 1}}}
	validated, err := fullyProtectedRoutes(entry)
	if err != nil || len(validated) != 2 {
		t.Fatalf("routes=%+v err=%v", validated, err)
	}
	created := session.Created{Session: domain.NewProtectionSession("session-0123456789abcdef", "", "http://127.0.0.1:1", time.Now(), time.Now().Add(time.Hour), []string{"route-primary", "route-fallback"}, nil), Routes: []session.RouteCredential{{RouteID: "route-fallback", Token: "fallback-token"}, {RouteID: "route-primary", Token: "primary-token"}}}
	credentials, err := bindRouteCredentials(routes, created)
	if err != nil || credentials["route-primary"] != "primary-token" || credentials["route-fallback"] != "fallback-token" {
		t.Fatalf("credentials=%+v err=%v", credentials, err)
	}
	created.Routes[1].RouteID = "route-unknown"
	if _, err := bindRouteCredentials(routes, created); err == nil {
		t.Fatal("unknown route credential was accepted")
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

func TestManagementJSONRejectsUnboundedOrAmbiguousResponses(t *testing.T) {
	tests := []struct {
		name    string
		headers func(http.Header)
		body    string
	}{
		{name: "missing content type", body: `{}`},
		{name: "missing API version", headers: func(header http.Header) {
			header.Del(core.APIVersionHeader)
			header.Set("Content-Type", "application/json")
		}, body: `{}`},
		{name: "incompatible API version", headers: func(header http.Header) {
			header.Set(core.APIVersionHeader, "v2")
			header.Set("Content-Type", "application/json")
		}, body: `{}`},
		{name: "duplicate content type", headers: func(header http.Header) {
			header.Add("Content-Type", "application/json")
			header.Add("Content-Type", "application/json")
		}, body: `{}`},
		{name: "unsupported encoding", headers: func(header http.Header) {
			header.Set("Content-Type", "application/json")
			header.Set("Content-Encoding", "br")
		}, body: `{}`},
		{name: "ambiguous JSON", headers: func(header http.Header) {
			header.Set("Content-Type", "application/json")
		}, body: `{"status":"ok","status":"forged"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(core.APIVersionHeader, core.APIVersion)
				if test.headers != nil {
					test.headers(w.Header())
				}
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			var output map[string]string
			if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err == nil {
				t.Fatal("unsafe management response was accepted")
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, maxManagementResponseBytes+1))
	}))
	defer server.Close()
	var output map[string]string
	if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err == nil {
		t.Fatal("oversized management response was accepted")
	}
}

func TestManagementJSONDecodesStrictBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	var output struct {
		Status string `json:"status"`
	}
	if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err != nil || output.Status != "ok" {
		t.Fatalf("output=%+v error=%v", output, err)
	}
}

func TestManagementJSONSanitizesErrorResponses(t *testing.T) {
	for name, body := range map[string]string{
		"valid":   `{"error":"INVALID_SESSION"}`,
		"control": "{\"error\":\"BAD\\u001b[31m\"}",
		"unknown": `{"error":"INVALID_SESSION","detail":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(core.APIVersionHeader, core.APIVersion)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			err := managementJSON(context.Background(), http.MethodPost, server.URL, "01234567890123456789012345678901", nil, nil)
			if err == nil {
				t.Fatal("management error response was accepted")
			}
			message := err.Error()
			if strings.Contains(message, "\x1b") || name == "valid" && !strings.Contains(message, "INVALID_SESSION") || name != "valid" && strings.Contains(message, "secret") {
				t.Fatalf("unsafe or missing error message=%q", message)
			}
		})
	}
}

func TestManagementJSONRequestsIdentityEncoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding=%q", request.Header.Get("Accept-Encoding"))
		}
		if request.Header.Get(core.APIVersionHeader) != core.APIVersion {
			t.Errorf("management API version=%q", request.Header.Get(core.APIVersionHeader))
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	var output map[string]string
	if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err != nil {
		t.Fatal(err)
	}
}

func TestCompatibleCorePreflightRejectsMismatchedHealthVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","api_version":"v2"}`)
	}))
	defer server.Close()
	if err := requireCompatibleCore(context.Background(), server.URL, "01234567890123456789012345678901"); err == nil {
		t.Fatal("mismatched health API version was accepted before protected launch")
	}
}

func TestManagementPayloadRejectsAmbiguousDiagnostics(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":"v1"}{"schema_version":"v1"}`,
		`{"schema_version":"v1","schema_version":"forged"}`,
	} {
		response := &http.Response{
			Header: http.Header{"Content-Type": {"application/json"}, core.APIVersionHeader: {core.APIVersion}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		if _, err := readManagementResponse(response, maxManagementResponseBytes); err == nil {
			t.Fatalf("ambiguous diagnostic payload was accepted: %s", body)
		}
	}
}
