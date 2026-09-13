package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type fakeSystem struct {
	version, config string
	environment     map[string]string
	files           map[string]string
	readErrors      map[string]error
}

type inventorySystem struct {
	installed map[string]string
}

func (f inventorySystem) LookPath(name string) (string, error) {
	if _, ok := f.installed[name]; !ok {
		return "", errors.New("missing")
	}
	return "/bin/" + name, nil
}
func (f inventorySystem) Version(_ context.Context, executable string) (string, error) {
	name := strings.TrimPrefix(executable, "/bin/")
	return f.installed[name], nil
}
func (f inventorySystem) ReadFile(string) ([]byte, error) { return nil, os.ErrNotExist }
func (f inventorySystem) LookupEnv(string) (string, bool) { return "", false }
func (f inventorySystem) HomeDir() (string, error)        { return "/home/test", nil }

func (f fakeSystem) LookPath(name string) (string, error)            { return "/bin/" + name, nil }
func (f fakeSystem) Version(context.Context, string) (string, error) { return f.version, nil }

func (f fakeSystem) ReadFile(path string) ([]byte, error) {
	if err := f.readErrors[path]; err != nil {
		return nil, err
	}
	if content, ok := f.files[path]; ok {
		return []byte(content), nil
	}
	if f.config == "" {
		return nil, os.ErrNotExist
	}
	return []byte(f.config), nil
}
func (f fakeSystem) LookupEnv(key string) (string, bool) {
	value, ok := f.environment[key]
	return value, ok
}
func (f fakeSystem) HomeDir() (string, error) { return "/home/test", nil }

func TestCodexDiscoveryAndCustomProviderFailClosed(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "codex-cli 0.153.4"}, Verified: map[string]map[string]struct{}{"codex": {"0.153.4": {}}}}
	manifest, err := d.Inspect(context.Background(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Surfaces[0].Protocol != domain.ProtocolOpenAIResponses || !manifest.Surfaces[0].Required {
		t.Fatalf("manifest=%+v", manifest)
	}
	d.System = fakeSystem{version: "codex-cli 0.153.4", config: "model_provider = \"custom\""}
	if _, err := d.Inspect(context.Background(), "codex"); err == nil {
		t.Fatal("custom provider was guessed")
	}
}

func TestUnsupportedKnownAgentIsExplicitlyUnknown(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "Hermes Agent v0.20.6"}, Verified: map[string]map[string]struct{}{"hermes": {"0.20.6": {}}}}
	manifest, err := d.Inspect(context.Background(), "hermes")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Surfaces[0].Type != domain.SurfaceUnknown {
		t.Fatal("unsupported config was not explicit")
	}
}

func TestHermesDiscoveryUsesVersionedConfigSurfaceEnumeration(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "Hermes Agent v0.20.6", config: hermesConfigFixtureForDiscovery}, Verified: map[string]map[string]struct{}{"hermes": {"0.20.6": {}}}}
	manifest, err := d.Inspect(context.Background(), "hermes")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 4 {
		t.Fatalf("surfaces=%+v", manifest.Surfaces)
	}
	if manifest.Surfaces[0].ID != "primary" || manifest.Surfaces[0].Rewritable {
		t.Fatalf("primary coverage overstated: %+v", manifest.Surfaces[0])
	}
	for _, surface := range manifest.Surfaces {
		if strings.Contains(surface.Name, "secret") || strings.Contains(surface.ConfigSource, "secret") {
			t.Fatalf("manifest retained a credential: %+v", surface)
		}
	}
}

func TestHermesDiscoveryHonorsAbsoluteHermesHome(t *testing.T) {
	customHome := "/srv/hermes-profile"
	d := Discoverer{System: fakeSystem{
		version:     "Hermes Agent v0.20.6",
		environment: map[string]string{"HERMES_HOME": customHome},
		files:       map[string]string{filepath.Join(customHome, "config.yaml"): hermesConfigFixtureForDiscovery},
	}, Verified: map[string]map[string]struct{}{"hermes": {"0.20.6": {}}}}
	manifest, err := d.Inspect(context.Background(), "hermes")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 4 || manifest.Surfaces[0].ConfigSource != filepath.Join(customHome, "config.yaml") {
		t.Fatalf("manifest=%+v", manifest)
	}
	for _, value := range []string{"relative/profile", "bad\x00profile"} {
		d.System = fakeSystem{version: "Hermes Agent v0.20.6", environment: map[string]string{"HERMES_HOME": value}}
		if _, err := d.Inspect(context.Background(), "hermes"); err == nil {
			t.Fatalf("unsafe HERMES_HOME %q was accepted", value)
		}
	}
}

func TestHermesDiscoveryFailsClosedOnUnreadableConfiguration(t *testing.T) {
	path := "/home/test/.hermes/config.yaml"
	d := Discoverer{System: fakeSystem{version: "Hermes Agent v0.20.6", readErrors: map[string]error{path: os.ErrPermission}}, Verified: map[string]map[string]struct{}{"hermes": {"0.20.6": {}}}}
	if _, err := d.Inspect(context.Background(), "hermes"); err == nil {
		t.Fatal("unreadable Hermes configuration was treated as absent")
	}
}

func TestOpenClawDiscoveryUsesManagedDiscoveryOnlySurfaces(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "OpenClaw 1.2.3", config: `{
  agents: { defaults: { model: { primary: "corp/main", fallbacks: ["corp/backup"] } } },
  models: { providers: { corp: { baseUrl: "https://models.example/v1", api: "openai-completions", apiKey: "secret" } } },
}`}, Verified: map[string]map[string]struct{}{"openclaw": {"1.2.3": {}}}}
	manifest, err := d.Inspect(context.Background(), "openclaw")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Agent.Mode != domain.ModeManaged || len(manifest.Surfaces) != 2 {
		t.Fatalf("manifest=%+v", manifest)
	}
	for _, surface := range manifest.Surfaces {
		if surface.Rewritable || surface.Protocol != domain.ProtocolOpenAIChat || surface.Metadata["model_ref"] == "" {
			t.Fatalf("surface overstated or incomplete: %+v", surface)
		}
	}
}

func TestUnverifiedOpenClawStillReturnsRiskManifest(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "OpenClaw 9.9.9", config: `{
  agents: { defaults: { model: "corp/main" } },
  models: { providers: { corp: { baseUrl: "https://models.example/v1", api: "openai-completions" } } },
}`}, Verified: map[string]map[string]struct{}{}}
	manifest, err := d.Inspect(context.Background(), "openclaw")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Agent.Metadata["compatibility"] != "unverified" || len(manifest.Surfaces) != 1 || manifest.Surfaces[0].Rewritable {
		t.Fatalf("manifest=%+v", manifest)
	}
}

func TestClineDiscoveryCombinesProviderAndMCPStoresConservatively(t *testing.T) {
	dataDir := "/home/test/.cline/data"
	d := Discoverer{System: fakeSystem{version: "cline 3.0.21", files: map[string]string{
		filepath.Join(dataDir, "settings", "providers.json"):          `{"version":1,"providers":{"corp":{"settings":{"provider":"openai","model":"main","baseUrl":"https://models.example/v1","apiKey":"secret-value"}}}}`,
		filepath.Join(dataDir, "settings", "cline_mcp_settings.json"): `{"mcpServers":{"local":{"command":"server","env":{"TOKEN":"secret-value"}},"remote":{"type":"streamableHttp","url":"https://mcp.example/mcp","headers":{"Authorization":"secret-value"}}}}`,
	}}, Verified: map[string]map[string]struct{}{"cline": {"3.0.21": {}}}}
	manifest, err := d.Inspect(context.Background(), "cline")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 4 {
		t.Fatalf("surfaces=%+v", manifest.Surfaces)
	}
	counts := map[domain.SurfaceType]int{}
	for _, surface := range manifest.Surfaces {
		counts[surface.Type]++
		if surface.Rewritable || strings.Contains(surface.Name, "secret-value") || strings.Contains(surface.ConfigSource, "secret-value") {
			t.Fatalf("surface overstated or retained credentials: %+v", surface)
		}
	}
	if counts[domain.SurfaceModelPrimary] != 1 || counts[domain.SurfaceMCPHTTP] != 1 || counts[domain.SurfaceMCPStdio] != 1 || counts[domain.SurfaceUnknown] != 1 {
		t.Fatalf("surface counts=%+v", counts)
	}
}

func TestCursorDiscoveryEnumeratesGlobalMCPAndKeepsOtherRoutesUnknown(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "Cursor 3.19.19", config: `{
  "mcpServers": {
    "local": { "command": "server", "env": { "TOKEN": "secret-value" } },
    "remote": { "type": "streamableHttp", "url": "https://mcp.example/mcp", "headers": { "Authorization": "secret-value" } }
  }
}`}, Verified: map[string]map[string]struct{}{"cursor": {"3.19.19": {}}}}
	manifest, err := d.Inspect(context.Background(), "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 5 {
		t.Fatalf("surfaces=%+v", manifest.Surfaces)
	}
	counts := map[domain.SurfaceType]int{}
	for _, surface := range manifest.Surfaces {
		counts[surface.Type]++
		if surface.Rewritable || strings.Contains(surface.Name, "secret-value") || strings.Contains(surface.ConfigSource, "secret-value") {
			t.Fatalf("surface overstated or retained credentials: %+v", surface)
		}
	}
	if counts[domain.SurfaceMCPHTTP] != 1 || counts[domain.SurfaceMCPStdio] != 1 || counts[domain.SurfaceUnknown] != 3 {
		t.Fatalf("surface counts=%+v", counts)
	}
}

func TestZedDiscoveryEnumeratesExplicitSurfacesAndUnknownDynamicRoutes(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "Zed 1.2.3", config: `{
  "language_models": { "openai_compatible": { "corp": { "api_url": "https://models.example/v1", "available_models": [{ "name": "main" }], "custom_headers": { "Authorization": "secret-value" } } } },
  "context_servers": { "local": { "command": "server" }, "remote": { "url": "https://mcp.example/mcp", "headers": { "Authorization": "secret-value" } } }
}`}, Verified: map[string]map[string]struct{}{"zed": {"1.2.3": {}}}}
	manifest, err := d.Inspect(context.Background(), "zed")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 5 {
		t.Fatalf("surfaces=%+v", manifest.Surfaces)
	}
	counts := map[domain.SurfaceType]int{}
	for _, surface := range manifest.Surfaces {
		counts[surface.Type]++
		if surface.Rewritable || strings.Contains(surface.Name, "secret-value") || strings.Contains(surface.ConfigSource, "secret-value") {
			t.Fatalf("surface overstated or retained credentials: %+v", surface)
		}
	}
	if counts[domain.SurfaceModelPrimary] != 1 || counts[domain.SurfaceMCPHTTP] != 1 || counts[domain.SurfaceMCPStdio] != 1 || counts[domain.SurfaceUnknown] != 2 {
		t.Fatalf("surface counts=%+v manifest=%+v", counts, manifest.Surfaces)
	}
}

func TestOpenCodeDiscoveryEnumeratesConfigAndKeepsOverrideRisksExplicit(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "opencode 1.2.3", config: `{
  "model": "corp/main",
  "small_model": "anthropic/haiku",
  "provider": { "corp": { "npm": "@ai-sdk/openai-compatible", "options": { "baseURL": "https://models.example/v1", "apiKey": "secret-value" } } },
  "mcp": {
    "local": { "type": "local", "command": ["server"] },
    "remote": { "type": "remote", "url": "https://mcp.example/rpc", "headers": { "Authorization": "secret-value" } }
  }
}`}, Verified: map[string]map[string]struct{}{"opencode": {"1.2.3": {}}}}
	manifest, err := d.Inspect(context.Background(), "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 5 {
		t.Fatalf("surfaces=%+v", manifest.Surfaces)
	}
	byID := make(map[string]domain.EgressSurface, len(manifest.Surfaces))
	for _, surface := range manifest.Surfaces {
		byID[surface.ID] = surface
		if surface.Rewritable || strings.Contains(surface.Name, "secret-value") || strings.Contains(surface.ConfigSource, "secret-value") {
			t.Fatalf("surface overstated or retained credentials: %+v", surface)
		}
	}
	if byID["primary"].Protocol != domain.ProtocolOpenAIChat || byID["mcp-remote"].Protocol != domain.ProtocolMCPStreamable || byID["mcp-local"].Protocol != domain.ProtocolLocalStdio {
		t.Fatalf("enumerated surfaces=%+v", manifest.Surfaces)
	}
	if byID["workspace-config-overrides"].Type != domain.SurfaceUnknown || !byID["workspace-config-overrides"].Required {
		t.Fatalf("workspace override risk missing: %+v", byID["workspace-config-overrides"])
	}
}

func TestOpenCodeInlineConfigOverrideIsExplicitlyUnknown(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "opencode 1.2.3", config: `{"model":"anthropic/main"}`, environment: map[string]string{"OPENCODE_CONFIG_CONTENT": `{"model":"private/secret"}`}}, Verified: map[string]map[string]struct{}{"opencode": {"1.2.3": {}}}}
	manifest, err := d.Inspect(context.Background(), "opencode")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, surface := range manifest.Surfaces {
		if surface.ID == "inline-config-overrides" {
			found = surface.Type == domain.SurfaceUnknown && surface.Required
		}
		if strings.Contains(surface.Name, "private/secret") || strings.Contains(surface.ConfigSource, "private/secret") {
			t.Fatalf("inline config content retained: %+v", surface)
		}
	}
	if !found {
		t.Fatalf("inline override risk missing: %+v", manifest.Surfaces)
	}
}

const hermesConfigFixtureForDiscovery = `
model:
  provider: custom
  base_url: https://models.example/v1
  api_key: secret-value
auxiliary:
  vision:
    provider: main
mcp_servers:
  local:
    command: npx
  remote:
    url: https://mcp.example/rpc
    headers:
      Authorization: Bearer secret-value
`

func TestClaudeAPIKeyDiscoveryUsesIndirectRuntimeSource(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "2.1.220", environment: map[string]string{"ANTHROPIC_API_KEY": "must-not-enter-manifest"}}, Verified: map[string]map[string]struct{}{"claude": {"2.1.220": {}}}}
	manifest, err := d.Inspect(context.Background(), "claude")
	if err != nil {
		t.Fatal(err)
	}
	auth := manifest.Surfaces[0].Auth
	if auth.Type != domain.AuthAnthropicKey || auth.Source != "environment:ANTHROPIC_API_KEY" || strings.Contains(auth.Source, "must-not-enter-manifest") {
		t.Fatalf("auth=%+v", auth)
	}
}

func TestClaudeDiscoveryRejectsDuplicateConfigurationKeys(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "2.1.220", config: `{"env":{"ANTHROPIC_BASE_URL":"https://safe.example","ANTHROPIC_BASE_URL":"https://hidden.example"}}`}, Verified: map[string]map[string]struct{}{"claude": {"2.1.220": {}}}}
	if _, err := d.Inspect(context.Background(), "claude"); err == nil {
		t.Fatal("Claude settings with duplicate upstream were accepted")
	}
}

func TestCodexAndClaudeDiscoveryFailClosedOnUnreadableConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, version, path string
	}{
		{"codex", "0.153.4", "/home/test/.codex/config.toml"},
		{"claude", "2.1.220", "/home/test/.claude/settings.json"},
	} {
		d := Discoverer{System: fakeSystem{version: test.version, readErrors: map[string]error{test.path: os.ErrPermission}}, Verified: map[string]map[string]struct{}{test.name: {test.version: {}}}}
		if _, err := d.Inspect(context.Background(), test.name); err == nil {
			t.Fatalf("%s unreadable configuration was treated as absent", test.name)
		}
	}
}

func TestOSSystemBoundsConfigurationReads(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "large.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxAgentConfigBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := (OSSystem{}).ReadFile(path); err == nil {
		t.Fatal("oversized agent configuration was accepted")
	}
	regular := filepath.Join(directory, "regular.json")
	if err := os.WriteFile(regular, []byte(`{"safe":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, err := (OSSystem{}).ReadFile(regular); err != nil || string(content) != `{"safe":true}` {
		t.Fatalf("regular config=%q error=%v", content, err)
	}
	if _, err := (OSSystem{}).ReadFile(directory); err == nil {
		t.Fatal("configuration directory was accepted as a file")
	}
	link := filepath.Join(directory, "linked.json")
	if err := os.Symlink(regular, link); err == nil {
		if _, err := (OSSystem{}).ReadFile(link); err == nil {
			t.Fatal("symlinked agent configuration was accepted")
		}
	}
}

func TestOSSystemBoundsVersionCommandOutputAndRuntime(t *testing.T) {
	script := filepath.Join(t.TempDir(), "noisy-agent")
	content := []byte("#!/bin/sh\nwhile true; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done\n")
	if err := os.WriteFile(script, content, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	output, err := (OSSystem{}).Version(ctx, script)
	if err == nil || len(output) > maxAgentVersionBytes {
		t.Fatalf("output bytes=%d error=%v", len(output), err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("version process exceeded its caller deadline: elapsed=%v", time.Since(started))
	}
}

func TestOSSystemBoundsVersionWaitForInheritedOutputPipes(t *testing.T) {
	directory := t.TempDir()
	markerPath := filepath.Join(directory, "descendant-survived")
	script := filepath.Join(directory, "forking-agent")
	content := []byte("#!/bin/sh\n(sleep 1; echo survived > \"" + markerPath + "\") &\n")
	if err := os.WriteFile(script, content, 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := (OSSystem{}).Version(context.Background(), script)
	if err == nil {
		t.Fatal("version command with inherited open output pipe was accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatalf("version command waited for descendant output pipe: elapsed=%v", time.Since(started))
	}
	time.Sleep(1100 * time.Millisecond)
	if _, statErr := os.Stat(markerPath); !os.IsNotExist(statErr) {
		t.Fatalf("version command descendant survived process-group cleanup: %v", statErr)
	}
}

func TestProtectedCLIDiscoveryBindsEnvironmentProxyAfterDLP(t *testing.T) {
	for _, name := range []string{"codex", "claude"} {
		version := "0.153.4"
		if name == "claude" {
			version = "2.1.220"
		}
		d := Discoverer{System: fakeSystem{version: name + " " + version, environment: map[string]string{"HTTPS_PROXY": "http://proxy-user:proxy-secret@proxy.example:8080", "ANTHROPIC_API_KEY": "provider-secret"}}, Verified: map[string]map[string]struct{}{name: {version: {}}}}
		manifest, err := d.Inspect(context.Background(), name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		surface := manifest.Surfaces[0]
		if surface.Network == nil || surface.Network.Type != domain.NetworkSystemProxy || surface.Network.Endpoint != "" {
			t.Fatalf("%s network=%+v", name, surface.Network)
		}
		encoded, _ := json.Marshal(manifest)
		if strings.Contains(string(encoded), "proxy-secret") || strings.Contains(string(encoded), "provider-secret") {
			t.Fatalf("%s manifest retained credentials: %s", name, encoded)
		}
	}
}

func TestClaudeOAuthDiscoveryDoesNotClaimRewritableCoverage(t *testing.T) {
	d := Discoverer{System: fakeSystem{version: "2.1.220"}, Verified: map[string]map[string]struct{}{"claude": {"2.1.220": {}}}}
	manifest, err := d.Inspect(context.Background(), "claude")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Surfaces[0].Rewritable || manifest.Surfaces[0].Auth.Type != domain.AuthPassthrough {
		t.Fatalf("OAuth surface overstated coverage: %+v", manifest.Surfaces[0])
	}
}

func TestAutomaticDiscoveryReportsUnknownVersionsWithoutClaimingCompatibility(t *testing.T) {
	d := Discoverer{System: inventorySystem{installed: map[string]string{
		"codex":    "codex-cli 0.153.4",
		"openclaw": "OpenClaw 9.9.9",
		"cline":    "development build",
	}}, Verified: map[string]map[string]struct{}{"codex": {"0.153.4": {}}}}
	got := d.DetectAll(context.Background())
	if len(got) != 3 || got[0].Agent != "codex" || got[0].Status != DetectionVerified || got[1].Agent != "openclaw" || got[1].Status != DetectionUnverified || got[2].Agent != "cline" || got[2].Status != DetectionVersionUnknown {
		t.Fatalf("detections=%+v", got)
	}
}
