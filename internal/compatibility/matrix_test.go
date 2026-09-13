package compatibility

import (
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestMatrixIsExplicitAndPlatformScoped(t *testing.T) {
	seen := map[string]struct{}{}
	for _, record := range Current() {
		key := strings.Join([]string{record.Agent, record.Version, record.Platform, string(record.Mode), string(record.Surface), string(record.Protocol), string(record.Auth)}, "|")
		if record.Agent == "" || record.Version == "" || record.Platform == "" || !record.Mode.Valid() || !record.Surface.Valid() || !record.Protocol.Valid() || record.Auth != "" && !record.Auth.Valid() || !record.Coverage.Valid() || record.Verification == "" || record.Notes == "" {
			t.Fatalf("incomplete record: %+v", record)
		}
		if record.Coverage == domain.CoverageProtected && (record.Surface == domain.SurfaceUnknown || record.Protocol == domain.ProtocolUnknown || !record.Auth.Valid() || record.Verification != VerificationLaunchSmoke) {
			t.Fatalf("protected compatibility is not backed by an exact verified surface: %+v", record)
		}
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate compatibility record: %s", key)
		}
		seen[key] = struct{}{}
	}
	claude := ForAgent("claude", "2.1.220", "linux")
	if len(claude) != 2 || claude[0].Coverage != domain.CoverageProtected || claude[1].Coverage != domain.CoverageObserved {
		t.Fatalf("Claude authentication modes are not explicit: %+v", claude)
	}
	if len(VerifiedVersions("unsupported-os")) != 0 {
		t.Fatal("versions leaked across platform verification boundaries")
	}
	verified := VerifiedVersions("linux")
	if _, ok := verified["codex"]["0.153.4"]; !ok {
		t.Fatal("protected launch-smoke version was omitted")
	}
	if _, ok := verified["claude"]["2.1.220"]; !ok {
		t.Fatal("version with a protected launch-smoke authentication path was omitted")
	}
	if _, ok := verified["hermes"]["0.20.6"]; !ok {
		t.Fatal("Hermes protected launch-smoke version was omitted")
	}
	hermes := ForAgent("hermes", "0.20.6", "linux")
	if len(hermes) != 6 {
		t.Fatalf("Hermes verified surfaces=%+v", hermes)
	}
	for _, record := range hermes {
		if record.Surface == domain.SurfaceUnknown || record.Protocol == domain.ProtocolUnknown {
			t.Fatalf("Hermes compatibility overstates unknown coverage: %+v", record)
		}
	}
	for _, discoveryOnly := range []string{"cursor"} {
		if _, ok := verified[discoveryOnly]; ok {
			t.Fatalf("discovery-only %s version was allowed to claim rewritable compatibility", discoveryOnly)
		}
	}
}
