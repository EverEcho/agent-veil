package egress

import (
	"github.com/agentveil/agentveil/internal/domain"
	"testing"
)

func TestUnexpectedEgressIsNeverCalledProtected(t *testing.T) {
	results := Assess([]Connection{{ProcessID: 1, Host: "api.example", Port: 443, ThroughRouteID: "route"}, {ProcessID: 2, Host: "unknown.example", Port: 443}}, []Expected{{ProcessID: 1, Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}})
	if results[0].Status != domain.CoverageProtected || results[1].Status == domain.CoverageProtected || results[1].Risk == nil {
		t.Fatalf("results=%+v", results)
	}
}
