package egress

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestUnexpectedEgressIsNeverCalledProtected(t *testing.T) {
	results := Assess([]Connection{{ProcessID: 1, Host: "api.example", Port: 443, ThroughRouteID: "route"}, {ProcessID: 2, Host: "unknown.example", Port: 443}}, []Expected{{ProcessID: 1, Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}})
	if results[0].Status != StatusContentProtected || results[0].SurfaceID != "primary" || results[1].Status != StatusObserved || results[1].Risk == nil || results[1].Risk.Code != domain.RiskUnexpectedEgress {
		t.Fatalf("results=%+v", results)
	}
}

func TestBlockedEgressIsDistinctFromContentProtection(t *testing.T) {
	connections := []Connection{
		{ProcessID: 1, Host: "API.EXAMPLE.", Port: 443, ThroughRouteID: "route", Blocked: true},
		{ProcessID: 2, Host: "blocked.example", Port: 443, Blocked: true},
	}
	expected := []Expected{{ProcessID: 1, Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}}
	results := Assess(connections, expected)
	for _, result := range results {
		if result.Status != StatusBlocked || result.Status == StatusContentProtected || result.Risk == nil {
			t.Fatalf("blocked connection was overstated: %+v", result)
		}
	}
}

func TestIncompleteExpectedRouteCannotClaimContentProtection(t *testing.T) {
	connection := Connection{ProcessID: 1, Host: "api.example", Port: 443}
	for _, expected := range []Expected{
		{ProcessID: 1, Host: "api.example", Port: 443, SurfaceID: "primary"},
		{ProcessID: 1, Host: "api.example", Port: 443, RouteID: "route"},
	} {
		result := Assess([]Connection{connection}, []Expected{expected})[0]
		if result.Status != StatusObserved || result.Risk == nil {
			t.Fatalf("incomplete route was trusted: %+v", result)
		}
	}
}
