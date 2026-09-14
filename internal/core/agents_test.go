package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

func TestDiscoveryAPIUsesAuthenticatedInjectedInventory(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithDiscoverer(fixedDiscoverer{{Agent: "codex", Executable: "/bin/codex", Version: "1.2.3", Status: discovery.DetectionUnverified}})
	request := httptest.NewRequest(http.MethodGet, "/v1/discovery", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.getDiscovery)(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var detections []discovery.Detection
	if err := json.Unmarshal(recorder.Body.Bytes(), &detections); err != nil {
		t.Fatal(err)
	}
	if len(detections) != 1 || detections[0].Agent != "codex" || detections[0].Status != discovery.DetectionUnverified {
		t.Fatalf("detections=%+v", detections)
	}
}

func TestInspectionPreviewReturnsManifestAndTruthfulCoverage(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "openclaw", Kind: "openclaw", Version: "9.9.9", Mode: domain.ModeManaged, Metadata: map[string]string{"compatibility": "unverified"}}, Surfaces: []domain.EgressSurface{
		{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIChat, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: "fixture", Rewritable: false, Required: true},
		{ID: "version-compatibility", Name: "Unverified version egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, ConfigSource: "fixture", Required: true},
	}}
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{domain.ProtocolOpenAIChat: {Observable: true}}})
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithRegistry(reg).WithDiscoverer(fixedInspectableDiscoverer{manifest: manifest})
	request := httptest.NewRequest(http.MethodGet, "/v1/discovery/openclaw", nil)
	request.SetPathValue("id", "openclaw")
	recorder := httptest.NewRecorder()
	s.getInspection(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Manifest      domain.AgentManifest   `json:"manifest"`
		Plan          domain.ProtectionPlan  `json:"protection_plan"`
		Compatibility []compatibility.Record `json:"compatibility"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Agent.Metadata["compatibility"] != "unverified" || result.Plan.Summary.Total != 2 || result.Plan.Summary.Observed != 1 || result.Plan.Summary.Unprotected != 1 || result.Plan.Summary.Protected != 0 || len(result.Plan.Routes) != 0 || len(result.Plan.Risks) != 2 || len(reg.List()) != 0 {
		t.Fatalf("preview mutated registry or overstated coverage: %+v", result)
	}
}
