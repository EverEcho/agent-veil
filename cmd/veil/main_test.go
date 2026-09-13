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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
	nativesdk "github.com/agentveil/agentveil/sdk/native"
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

func TestWriteLaunchProtectionPlanShowsCoverageWithoutSecretsOrUpstreams(t *testing.T) {
	entry := registry.Entry{
		Manifest: domain.AgentManifest{
			Agent:    domain.AgentInstance{Kind: "hermes", Version: "0.20.6"},
			Surfaces: []domain.EgressSurface{{ID: "primary", Name: "Primary Model", Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "https", Host: "secret-upstream.example", Port: 443}, Auth: domain.AuthStrategy{Source: "environment:SECRET_KEY"}}},
		},
		Plan: domain.ProtectionPlan{
			Coverage: []domain.SurfaceCoverage{{SurfaceID: "primary", Status: domain.CoverageProtected, Reason: "rewritten through an authenticated route", RouteID: "route-secret"}},
			Summary:  domain.CoverageSummary{Total: 1, Protected: 1},
		},
	}
	var output bytes.Buffer
	if err := writeLaunchProtectionPlan(&output, entry); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "hermes 0.20.6") || !strings.Contains(text, "[protected] Primary Model (openai_responses)") || !strings.Contains(text, "1 protected") {
		t.Fatalf("launch plan omitted required coverage: %q", text)
	}
	for _, secret := range []string{"secret-upstream.example", "SECRET_KEY", "route-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("launch plan leaked %q: %q", secret, text)
		}
	}
}

func TestWriteLaunchProtectionPlanRejectsUnknownSurface(t *testing.T) {
	entry := registry.Entry{Manifest: domain.AgentManifest{Agent: domain.AgentInstance{Kind: "test"}}, Plan: domain.ProtectionPlan{Coverage: []domain.SurfaceCoverage{{SurfaceID: "missing", Status: domain.CoverageProtected}}}}
	if err := writeLaunchProtectionPlan(&bytes.Buffer{}, entry); err == nil {
		t.Fatal("unknown plan surface was displayed")
	}
}

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

func TestNestedRunParsingPreservesChildArguments(t *testing.T) {
	name, child, err := parseNestedRun([]string{"codex", "--", "exec", "delegated task"})
	if err != nil || name != "codex" || strings.Join(child, "|") != "exec|delegated task" {
		t.Fatalf("name=%q child=%v err=%v", name, child, err)
	}
	if _, _, err := parseNestedRun(nil); err == nil {
		t.Fatal("missing nested target was accepted")
	}
}

func TestPrepareNestedLaunchBindsVerifiedCapabilityTransports(t *testing.T) {
	endpoint := "http://127.0.0.1:1234"
	parentID := "session-0123456789abcdef"
	routeID := "route-primary-g1"
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	baseChild := nativesdk.ChildSession{
		Session: nativesdk.ProtectionSession{ID: "session-fedcba9876543210", ParentSessionID: parentID, CoreEndpoint: endpoint, RouteIDs: []string{routeID}},
		Routes:  []nativesdk.RouteCredential{{RouteID: routeID, Token: token}},
	}
	agent := domain.AgentInstance{Kind: "codex", Mode: domain.ModeLaunch, Executable: "/bin/true"}
	for _, transports := range [][]string{{nativesdk.CapabilityTransportHeaders}, {nativesdk.CapabilityTransportHeaders, nativesdk.CapabilityTransportPath}} {
		child := baseChild
		child.Protocol = domain.ProtocolOpenAIResponses
		child.CapabilityTransports = transports
		launch, args, err := prepareNestedLaunch("codex", agent, endpoint, parentID, routeID, child, []string{"exec", "task"}, false)
		if err != nil || launch.Environment["VEIL_PARENT_SESSION"] != parentID || launch.Environment["VEIL_ROUTE_ID"] != routeID {
			t.Fatalf("transports=%q launch=%+v err=%v", transports, launch, err)
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "env_http_headers") || strings.Contains(joined, token) || strings.Contains(joined, "/__veil/") {
			t.Fatalf("transports=%q exposed or omitted nested headers: args=%v", transports, args)
		}
	}
	claudeChild := baseChild
	claudeChild.Protocol = domain.ProtocolAnthropic
	claudeChild.CapabilityTransports = []string{nativesdk.CapabilityTransportAnthropicAPIKey}
	claudeAgent := domain.AgentInstance{Kind: "claude", Mode: domain.ModeLaunch, Executable: "/bin/true"}
	launch, _, err := prepareNestedLaunch("claude", claudeAgent, endpoint, parentID, routeID, claudeChild, nil, false)
	if err != nil || launch.Environment["ANTHROPIC_BASE_URL"] != endpoint+"/route/"+routeID || launch.Environment["ANTHROPIC_API_KEY"] != "veil-v1:"+claudeChild.Session.ID+":"+token {
		t.Fatalf("nested Claude launch=%+v err=%v", launch, err)
	}
	claudeChild.Protocol = domain.ProtocolOpenAIResponses
	if _, _, err := prepareNestedLaunch("claude", claudeAgent, endpoint, parentID, routeID, claudeChild, nil, false); err == nil {
		t.Fatal("nested Claude accepted a mismatched protocol")
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
		[]string{"PATH=/bin", "VEIL_ADMIN_TOKEN=management-secret", "veil_admin_token=case-variant", "VEIL_PARENT_SESSION=stale-parent", "veil_session_id=stale-session", "veil_route_id=stale-route"},
		map[string]string{"VEIL_SESSION_ID": "session", "VEIL_ROUTE_ID": "route", "VEIL_ADMIN_TOKEN": "override-secret"},
	)
	joined := strings.Join(environment, "\n")
	if strings.Contains(strings.ToLower(joined), "veil_admin_token=") || strings.Contains(joined, "stale-parent") || strings.Contains(joined, "stale-session") || strings.Contains(joined, "stale-route") || strings.Count(strings.ToLower(joined), "veil_session_id=") != 1 || strings.Count(strings.ToLower(joined), "veil_route_id=") != 1 || !strings.Contains(joined, "VEIL_SESSION_ID=session") || !strings.Contains(joined, "VEIL_ROUTE_ID=route") || !strings.Contains(joined, "PATH=/bin") {
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

func TestWriteCompatibilityReportUsesAuthenticatedVersionedCoreAPI(t *testing.T) {
	token := "01234567890123456789012345678901"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/compatibility" || request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion {
			t.Fatalf("request path=%q headers=%v", request.URL.Path, request.Header)
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"agent":"codex","version":"0.153.4","platform":"linux","mode":"launch","surface":"model_primary","protocol":"openai_responses","auth":"passthrough","coverage":"protected","verification":"launch_smoke","notes":"verified"}]`)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := writeCompatibilityReport(&output, server.URL, token); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"surface": "model_primary"`) || !strings.Contains(output.String(), `"verification": "launch_smoke"`) {
		t.Fatalf("compatibility output=%s", output.String())
	}
	if err := writeCompatibilityReport(nil, server.URL, token); err == nil {
		t.Fatal("nil compatibility writer was accepted")
	}
}

func TestOfflineCompatibilityReportUsesTheValidatedBuildMatrix(t *testing.T) {
	var output bytes.Buffer
	if err := writeOfflineCompatibilityReport(&output); err != nil {
		t.Fatal(err)
	}
	var records []compatibility.Record
	if err := json.Unmarshal(output.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != len(compatibility.Current()) || len(records) == 0 {
		t.Fatalf("records=%d current=%d", len(records), len(compatibility.Current()))
	}
	for _, record := range records {
		if record.Coverage == domain.CoverageProtected && (record.Surface == domain.SurfaceUnknown || record.Protocol == domain.ProtocolUnknown || record.Verification != compatibility.VerificationLaunchSmoke) {
			t.Fatalf("offline release report overstated coverage: %+v", record)
		}
	}
	if err := writeOfflineCompatibilityReport(nil); err == nil {
		t.Fatal("nil offline compatibility writer was accepted")
	}
}

func TestRulesCommandUsesAuthenticatedVersionedManagementAPI(t *testing.T) {
	const token = "01234567890123456789012345678901"
	type requestRecord struct{ method, path string }
	var requests []requestRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		requests = append(requests, requestRecord{request.Method, request.URL.EscapedPath()})
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"active":"1.0.0","versions":[{"schema_version":"v1","version":"1.0.0","size":2,"sha256":"00","signature":"AA=="}]}`)
			return
		}
		if request.Method == http.MethodPost {
			var input struct {
				Manifest       rulestore.Manifest `json:"manifest"`
				ArtifactBase64 string             `json:"artifact_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Manifest.Version != "2.0.0" || input.ArtifactBase64 != base64.StdEncoding.EncodeToString([]byte("{}")) {
				t.Fatalf("install input=%+v err=%v", input, err)
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	artifactPath := filepath.Join(directory, "rules.json")
	if err := os.WriteFile(manifestPath, []byte(`{"schema_version":"v1","version":"2.0.0","size":2,"sha256":"00","signature":"AA=="}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	for _, args := range [][]string{{"list"}, {"install", manifestPath, artifactPath}, {"activate", "2.0.0"}, {"deactivate"}, {"remove", "2.0.0"}} {
		if err := executeRulesCommand(context.Background(), &output, server.URL, token, args); err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	if !strings.Contains(output.String(), `"active": "1.0.0"`) {
		t.Fatalf("list output=%s", output.String())
	}
	want := []requestRecord{{http.MethodGet, "/v1/rules"}, {http.MethodPost, "/v1/rules"}, {http.MethodPut, "/v1/rules/active"}, {http.MethodDelete, "/v1/rules/active"}, {http.MethodDelete, "/v1/rules/2.0.0"}}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests=%+v want=%+v", requests, want)
	}
}

func TestRulesCommandRejectsUnsafeFilesAndArguments(t *testing.T) {
	if err := executeRulesCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", []string{"future"}); err == nil {
		t.Fatal("unknown rule command was accepted")
	}
	if err := executeRulesCommand(context.Background(), io.Discard, "https://example.com", "token", []string{"list"}); err == nil {
		t.Fatal("non-loopback rule management endpoint was accepted")
	}
	if err := executeRulesCommand(nil, io.Discard, "http://127.0.0.1:1", "token", []string{"list"}); err == nil {
		t.Fatal("nil context was accepted")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "link.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err == nil {
		if _, err := readCLIFile(link, 1024); err == nil {
			t.Fatal("symlinked CLI file was accepted")
		}
	}
	var manifest rulestore.Manifest
	if err := decodeStrictJSON([]byte(`{"schema_version":"v1","version":"one","version":"two"}`), &manifest); err == nil {
		t.Fatal("ambiguous manifest JSON was accepted")
	}
}

func TestModelsCommandStreamsAuthenticatedVersionedManagementAPI(t *testing.T) {
	const token = "01234567890123456789012345678901"
	type requestRecord struct{ method, path string }
	var requests []requestRecord
	artifactPayload := []byte("model-bytes")
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "2.0.0", Size: int64(len(artifactPayload)), SHA256: strings.Repeat("0", 64), Signature: "AA=="}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		requests = append(requests, requestRecord{request.Method, request.URL.EscapedPath()})
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		switch {
		case request.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"versions":[],"runtime":{"connected":false,"required":false,"active":false,"resource_state":"inactive"}}`)
		case request.Method == http.MethodPost:
			decodedManifest, decodeErr := base64.StdEncoding.DecodeString(request.Header.Get(core.ModelManifestHeader))
			body, readErr := io.ReadAll(request.Body)
			if request.Header.Get("Content-Type") != "application/octet-stream" || request.ContentLength != manifest.Size || decodeErr != nil || !bytes.Equal(decodedManifest, manifestPayload) || readErr != nil || !bytes.Equal(body, artifactPayload) {
				t.Fatalf("model upload content_type=%q length=%d manifest=%s body=%q decode_err=%v read_err=%v", request.Header.Get("Content-Type"), request.ContentLength, decodedManifest, body, decodeErr, readErr)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(manifestPayload)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	artifactPath := filepath.Join(directory, "model.bin")
	if err := os.WriteFile(manifestPath, manifestPayload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, artifactPayload, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	for _, args := range [][]string{{"list"}, {"install", manifestPath, artifactPath}, {"activate", "2.0.0"}, {"deactivate"}, {"remove", "2.0.0"}} {
		if err := executeModelsCommand(context.Background(), &output, server.URL, token, args); err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	if !strings.Contains(output.String(), `"resource_state": "inactive"`) {
		t.Fatalf("list output=%s", output.String())
	}
	want := []requestRecord{{http.MethodGet, "/v1/models"}, {http.MethodPost, "/v1/models"}, {http.MethodPut, "/v1/models/active"}, {http.MethodDelete, "/v1/models/active"}, {http.MethodDelete, "/v1/models/2.0.0"}}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests=%+v want=%+v", requests, want)
	}
}

func TestModelsCommandRejectsUnsafeInputs(t *testing.T) {
	if err := executeModelsCommand(context.Background(), io.Discard, "https://example.com", "token", []string{"list"}); err == nil {
		t.Fatal("non-loopback model management endpoint was accepted")
	}
	if err := managementJSONWithTimeout(nil, http.MethodGet, "http://127.0.0.1:1/v1/models", "token", nil, nil, time.Second); err == nil {
		t.Fatal("nil management context was accepted")
	}
	if err := managementJSONWithTimeout(context.Background(), http.MethodGet, "http://127.0.0.1:1/v1/models", "token", nil, nil, 0); err == nil {
		t.Fatal("zero management timeout was accepted")
	}
	redirectFollowed := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectFollowed = true }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if err := executeModelsCommand(context.Background(), io.Discard, redirect.URL, "token", []string{"list"}); err == nil {
		t.Fatal("redirecting model management response was accepted")
	}
	if redirectFollowed {
		t.Fatal("management client followed a redirect")
	}
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	artifactPath := filepath.Join(directory, "model.bin")
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: 2, SHA256: strings.Repeat("0", 64), Signature: "AA=="}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestPayload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("oversized"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := executeModelsCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", []string{"install", manifestPath, artifactPath}); err == nil || !strings.Contains(err.Error(), "size does not match") {
		t.Fatalf("mismatched model size error=%v", err)
	}
}

func TestPolicyCommandGetsAndAppliesValidatedDocuments(t *testing.T) {
	const token = "01234567890123456789012345678901"
	document := policy.Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: []policy.Rule{{Scope: policy.Scope{FindingType: "secret.private_key"}, Action: domain.ActionBlock}}}
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		methods = append(methods, request.Method)
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(document); err != nil {
				t.Fatal(err)
			}
			return
		}
		var applied policy.Document
		if request.Header.Get("Content-Type") != "application/json" || json.NewDecoder(request.Body).Decode(&applied) != nil || applied.SchemaVersion != "v1" || len(applied.Rules) != 1 {
			t.Fatalf("applied policy=%+v", applied)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.json")
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := executePolicyCommand(context.Background(), &output, server.URL, token, []string{"get"}); err != nil {
		t.Fatal(err)
	}
	if err := executePolicyCommand(context.Background(), io.Discard, server.URL, token, []string{"apply", path}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"default": "redact"`) || !slices.Equal(methods, []string{http.MethodGet, http.MethodPut}) {
		t.Fatalf("output=%s methods=%v", output.String(), methods)
	}
}

func TestPolicyCommandRejectsInvalidDocumentsBeforeUpload(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.json")
	payload := []byte(`{"schema_version":"v1","default":"REDACT","rules":[{"scope":{"finding_type":"secret.private_key"},"action":"BLOCK"},{"scope":{"finding_type":"secret.private_key"},"action":"ALLOW"}]}`)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := executePolicyCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", []string{"apply", path}); err == nil || !strings.Contains(err.Error(), "validate policy document") {
		t.Fatalf("duplicate policy scopes error=%v", err)
	}
	if err := executePolicyCommand(context.Background(), io.Discard, "https://example.com", "token", []string{"get"}); err == nil {
		t.Fatal("non-loopback policy endpoint was accepted")
	}
}

func TestApprovalsCommandListsMetadataAndResolvesOnce(t *testing.T) {
	const token = "01234567890123456789012345678901"
	const approvalID = "0123456789abcdef0123456789abcdef"
	approval := policy.Approval{ID: approvalID, Finding: domain.Finding{RuleID: "pii.email", Category: "pii.email", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: "/input", Start: 4, End: 8}, Confidence: 0.99, Detector: "regex", SuggestedAction: domain.ActionRedact}}
	var resolved domain.Action
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]policy.Approval{approval}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if request.Method != http.MethodPost || request.URL.EscapedPath() != "/v1/approvals/"+approvalID {
			t.Fatalf("request=%s %s", request.Method, request.URL.EscapedPath())
		}
		var body map[string]domain.Action
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		resolved = body["action"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := executeApprovalsCommand(context.Background(), &output, server.URL, token, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := executeApprovalsCommand(context.Background(), io.Discard, server.URL, token, []string{"resolve", approvalID, "redact"}); err != nil {
		t.Fatal(err)
	}
	if resolved != domain.ActionRedact || !strings.Contains(output.String(), `"category": "pii.email"`) || strings.Contains(output.String(), "original") {
		t.Fatalf("resolved=%q output=%s", resolved, output.String())
	}
}

func TestApprovalsCommandRejectsUntrustedIdentifiersAndActions(t *testing.T) {
	for _, args := range [][]string{{"resolve", "../policy", "allow"}, {"resolve", "0123456789abcdef0123456789abcdef", "ask"}, {"resolve", "0123456789ABCDEF0123456789ABCDEF", "block"}} {
		if err := executeApprovalsCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", args); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args=%v error=%v", args, err)
		}
	}
	if validApprovalID("0123456789abcdef0123456789abcdeg") {
		t.Fatal("non-hex approval identifier was accepted")
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
