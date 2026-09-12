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
