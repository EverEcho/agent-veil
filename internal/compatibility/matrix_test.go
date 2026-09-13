package compatibility

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestMatrixIsExplicitAndPlatformScoped(t *testing.T) {
	if err := Validate(Current()); err != nil {
		t.Fatal(err)
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
	if len(hermes) != 7 {
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

func TestValidationRejectsUnsupportedProtectedProtocol(t *testing.T) {
	invalid := Record{Agent: "agent", Version: "1.0.0", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceMCPHTTP, Protocol: domain.ProtocolLocalStdio, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "not a remotely inspected protocol"}
	if err := Validate([]Record{invalid}); err == nil {
		t.Fatal("protocol without a complete content adapter claimed Protected compatibility")
	}
}

func TestValidationRejectsMalformedAndDuplicateRecords(t *testing.T) {
	valid := Record{Agent: "agent", Version: "1.0.0", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "verified"}
	for name, candidate := range map[string][]Record{
		"unknown verification": {func() Record { record := valid; record.Verification = "assumed"; return record }()},
		"missing notes":        {func() Record { record := valid; record.Notes = " "; return record }()},
		"duplicate":            {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(candidate); err == nil {
				t.Fatal("invalid compatibility records were accepted")
			}
		})
	}
}
