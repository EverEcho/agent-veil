package egress

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestUnexpectedEgressIsNeverCalledProtected(t *testing.T) {
	results := Assess([]Connection{{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443, ThroughRouteID: "route"}, {ProcessIdentity: identity(2, 20), Host: "unknown.example", Port: 443}}, []Expected{{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}})
	if results[0].Status != StatusContentProtected || results[0].SurfaceID != "primary" || results[1].Status != StatusObserved || results[1].Risk == nil || results[1].Risk.Code != domain.RiskUnexpectedEgress {
		t.Fatalf("results=%+v", results)
	}
}

func TestBlockedEgressIsDistinctFromContentProtection(t *testing.T) {
	connections := []Connection{
		{ProcessIdentity: identity(1, 10), Host: "API.EXAMPLE.", Port: 443, ThroughRouteID: "route", Blocked: true},
		{ProcessIdentity: identity(2, 20), Host: "blocked.example", Port: 443, Blocked: true},
	}
	expected := []Expected{{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}}
	results := Assess(connections, expected)
	for _, result := range results {
		if result.Status != StatusBlocked || result.Status == StatusContentProtected || result.Risk == nil {
			t.Fatalf("blocked connection was overstated: %+v", result)
		}
	}
}

func TestIncompleteExpectedRouteCannotClaimContentProtection(t *testing.T) {
	connection := Connection{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443}
	for _, expected := range []Expected{
		{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443, SurfaceID: "primary"},
		{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443, RouteID: "route"},
	} {
		result := Assess([]Connection{connection}, []Expected{expected})[0]
		if result.Status != StatusObserved || result.Risk == nil {
			t.Fatalf("incomplete route was trusted: %+v", result)
		}
	}
}

func TestReusedProcessIDCannotClaimContentProtection(t *testing.T) {
	connection := Connection{ProcessIdentity: identity(1, 20), Host: "api.example", Port: 443, ThroughRouteID: "route"}
	expected := Expected{ProcessIdentity: identity(1, 10), Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}
	result := Assess([]Connection{connection}, []Expected{expected})[0]
	if result.Status != StatusObserved || result.Risk == nil || result.SurfaceID != "" {
		t.Fatalf("PID-reused process was trusted: %+v", result)
	}
}

func identity(processID int, startedAt uint64) ProcessIdentity {
	return ProcessIdentity{ProcessID: processID, StartedAt: startedAt}
}
