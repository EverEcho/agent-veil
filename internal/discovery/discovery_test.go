package discovery

import (
	"context"
	"errors"
	"github.com/agentveil/agentveil/internal/domain"
	"strings"
	"testing"
)

type fakeSystem struct {
	version, config string
	environment     map[string]string
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
func (f inventorySystem) ReadFile(string) ([]byte, error) { return nil, errors.New("unused") }
func (f inventorySystem) LookupEnv(string) (string, bool) { return "", false }
func (f inventorySystem) HomeDir() (string, error)        { return "/home/test", nil }

func (f fakeSystem) LookPath(name string) (string, error)            { return "/bin/" + name, nil }
func (f fakeSystem) Version(context.Context, string) (string, error) { return f.version, nil }
func (f fakeSystem) ReadFile(string) ([]byte, error) {
	if f.config == "" {
		return nil, errors.New("missing")
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

func TestUnsupportedEditorsExposeExplicitUnknownSurface(t *testing.T) {
	for _, name := range []string{"cursor", "cline"} {
		d := Discoverer{System: fakeSystem{version: name + " 9.9.9"}, Verified: map[string]map[string]struct{}{}}
		manifest, err := d.Inspect(context.Background(), name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(manifest.Surfaces) != 1 || manifest.Surfaces[0].Type != domain.SurfaceUnknown || manifest.Agent.Metadata["compatibility"] != "unverified" {
			t.Fatalf("%s manifest=%+v", name, manifest)
		}
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
