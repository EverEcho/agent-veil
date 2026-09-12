package compatibility

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestMatrixIsExplicitAndPlatformScoped(t *testing.T) {
	seen := map[string]struct{}{}
	for _, record := range Current() {
		key := record.Agent + "|" + record.Version + "|" + record.Platform + "|" + string(record.Auth)
		if record.Agent == "" || record.Version == "" || record.Platform == "" || !record.Coverage.Valid() || record.Verification == "" || record.Notes == "" {
			t.Fatalf("incomplete record: %+v", record)
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
}
