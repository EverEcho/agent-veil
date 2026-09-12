package integration

import (
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestHermesAllSlotsAndMCPBecomeIndependentSurfaces(t *testing.T) {
	inspector := Inspector{VerifiedVersions: map[string]map[string]struct{}{"hermes": {"1.0.0": {}}}}
	config := Config{AgentID: "h", Kind: "hermes", Version: "1.0.0", ConfigSource: "fixture-v1", Mode: domain.ModeLaunch, Slots: []Slot{
		{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, BaseURL: "https://api.example", Rewritable: true, Required: true},
		{ID: "vision", Name: "Vision", Type: domain.SurfaceVision, Protocol: domain.ProtocolOpenAIChat, BaseURL: "https://vision.example", Rewritable: true},
		{ID: "fallback-1", Name: "Fallback", Type: domain.SurfaceModelFallback, Protocol: domain.ProtocolAnthropic, BaseURL: "https://fallback.example", Rewritable: true},
	}, LocalMCP: []string{"filesystem"}}
	manifest, err := inspector.Inspect(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Surfaces) != 4 {
		t.Fatalf("surfaces=%+v", manifest.Surfaces)
	}
	seen := map[string]bool{}
	for _, surface := range manifest.Surfaces {
		if seen[surface.ID] {
			t.Fatal("surface ids are not independent")
		}
		seen[surface.ID] = true
	}
}

func TestUnknownVersionAndConflictingLaunchFailClosed(t *testing.T) {
	inspector := Inspector{VerifiedVersions: map[string]map[string]struct{}{"codex": {"1.0": {}}}}
	if _, err := inspector.Inspect(Config{Kind: "codex", Version: "2.0"}); err == nil {
		t.Fatal("unknown version accepted")
	}
	agent := domain.AgentInstance{ID: "c", Kind: "codex", Mode: domain.ModeLaunch, Executable: "/usr/bin/codex"}
	sessionID := "0123456789abcdef"
	routeToken := strings.Repeat("t", 32)
	if _, err := PrepareLaunch(agent, []string{"--provider=direct"}, "http://127.0.0.1:1", sessionID, "", routeToken); err == nil {
		t.Fatal("routing override accepted")
	}
	plan, err := PrepareLaunch(agent, []string{"exec"}, "http://127.0.0.1:1", sessionID, "fedcba9876543210", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Temporary || plan.Environment["VEIL_PARENT_SESSION"] != "fedcba9876543210" || plan.Environment["CODEX_DISABLE_WEBSOCKET"] != "1" {
		t.Fatalf("invalid launch plan: %+v", plan)
	}
}

func TestPrepareLaunchRejectsUntrustedExecutionInputs(t *testing.T) {
	base := domain.AgentInstance{ID: "c", Kind: "codex", Mode: domain.ModeLaunch, Executable: "/usr/bin/codex"}
	sessionID := "0123456789abcdef"
	token := strings.Repeat("t", 32)
	for _, test := range []struct {
		name     string
		agent    domain.AgentInstance
		endpoint string
		session  string
		token    string
	}{
		{"relative-executable", domain.AgentInstance{ID: "c", Kind: "codex", Mode: domain.ModeLaunch, Executable: "codex"}, "http://127.0.0.1:1", sessionID, token},
		{"remote-core", base, "http://api.example:443", sessionID, token},
		{"endpoint-path", base, "http://127.0.0.1:1/route", sessionID, token},
		{"short-session", base, "http://127.0.0.1:1", "short", token},
		{"short-token", base, "http://127.0.0.1:1", sessionID, "short"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PrepareLaunch(test.agent, nil, test.endpoint, test.session, "", test.token); err == nil {
				t.Fatal("unsafe launch input was accepted")
			}
		})
	}
}

func TestUnverifiedVersionCanOnlyProduceDiscoveryOnlyManifest(t *testing.T) {
	inspector := Inspector{VerifiedVersions: map[string]map[string]struct{}{}}
	manifest, err := inspector.Inspect(Config{AgentID: "openclaw", Kind: "openclaw", Version: "9.9.9", ConfigSource: "fixture", Mode: domain.ModeManaged, Observed: []Slot{{ID: "unknown", Name: "Unknown", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Agent.Metadata["compatibility"] != "unverified" || len(manifest.Surfaces) != 1 || manifest.Surfaces[0].Rewritable {
		t.Fatalf("manifest=%+v", manifest)
	}
	if _, err := inspector.Inspect(Config{AgentID: "unsafe", Kind: "unsafe", Version: "9.9.9", ConfigSource: "fixture", Mode: domain.ModeLaunch, Slots: []Slot{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, BaseURL: "https://api.example", Rewritable: true, Required: true}}}); err == nil {
		t.Fatal("unverified version claimed a rewritable surface")
	}
}

func TestInspectorPreservesSafeUpstreamBasePath(t *testing.T) {
	inspector := Inspector{VerifiedVersions: map[string]map[string]struct{}{"agent": {"1.0": {}}}}
	base := Config{AgentID: "a", Kind: "agent", Version: "1.0", ConfigSource: "fixture", Mode: domain.ModeLaunch, Slots: []Slot{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, BaseURL: "https://api.example.com/gateway/v1/", Rewritable: true, Required: true}}}
	manifest, err := inspector.Inspect(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.Surfaces[0].Upstream.Path; got != "/gateway/v1/" {
		t.Fatalf("base path=%q", got)
	}
	for _, suffix := range []string{"?token=secret", "#fragment"} {
		invalid := base
		invalid.Slots = append([]Slot(nil), base.Slots...)
		invalid.Slots[0].BaseURL += suffix
		if _, err := inspector.Inspect(invalid); err == nil {
			t.Fatalf("unsafe URL suffix %q accepted", suffix)
		}
	}
}

func TestInspectorCopiesSurfaceNetworkRoute(t *testing.T) {
	inspector := Inspector{VerifiedVersions: map[string]map[string]struct{}{"agent": {"1.0": {}}}}
	network := domain.NetworkRoute{Type: domain.NetworkSOCKS5, Endpoint: "socks5://127.0.0.1:1080"}
	config := Config{AgentID: "a", Kind: "agent", Version: "1.0", ConfigSource: "fixture", Mode: domain.ModeLaunch, Slots: []Slot{{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, BaseURL: "https://api.example", Network: &network, Rewritable: true, Required: true}}}
	manifest, err := inspector.Inspect(config)
	if err != nil {
		t.Fatal(err)
	}
	network.Endpoint = "socks5://127.0.0.1:9999"
	if manifest.Surfaces[0].Network == nil || manifest.Surfaces[0].Network.Endpoint != "socks5://127.0.0.1:1080" {
		t.Fatalf("network route was not independently copied: %+v", manifest.Surfaces[0].Network)
	}
}
