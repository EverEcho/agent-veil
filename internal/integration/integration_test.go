package integration

import (
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
	agent := domain.AgentInstance{ID: "c", Kind: "codex", Mode: domain.ModeLaunch, Executable: "codex"}
	if _, err := PrepareLaunch(agent, []string{"--provider=direct"}, "http://127.0.0.1:1", "s", "", "t"); err == nil {
		t.Fatal("routing override accepted")
	}
	plan, err := PrepareLaunch(agent, []string{"exec"}, "http://127.0.0.1:1", "s", "parent", "short-lived")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Temporary || plan.Environment["VEIL_PARENT_SESSION"] != "parent" || plan.Environment["CODEX_DISABLE_WEBSOCKET"] != "1" {
		t.Fatalf("invalid launch plan: %+v", plan)
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
