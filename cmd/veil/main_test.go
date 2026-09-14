package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/domain"
)

func useTestUserConfigDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", root)
		return filepath.Join(root, "Library", "Application Support")
	case "windows":
		t.Setenv("AppData", root)
		return root
	default:
		t.Setenv("XDG_CONFIG_HOME", root)
		return root
	}
}

func TestInspectionIncludesManifestAndTruthfulPlan(t *testing.T) {
	manifest := domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: "a", Kind: "test", Version: "99.0.0", Metadata: map[string]string{"compatibility": "unverified"}}, Surfaces: []domain.EgressSurface{
		{ID: "primary", Name: "Primary", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Upstream: &domain.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: domain.AuthStrategy{Type: domain.AuthBearer, Source: "environment:PROVIDER_TOKEN"}, ConfigSource: "test", Required: true},
		{ID: "unknown", Name: "Unknown", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, ConfigSource: "test", Required: true},
	}}
	var output bytes.Buffer
	if err := writeInspection(&output, manifest); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Manifest      domain.AgentManifest   `json:"manifest"`
		Plan          domain.ProtectionPlan  `json:"protection_plan"`
		Compatibility []compatibility.Record `json:"compatibility"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Agent.ID != "a" || result.Manifest.Agent.Metadata["compatibility"] != "unverified" || result.Plan.Summary.Total != 2 || result.Plan.Summary.Observed != 1 || result.Plan.Summary.Unprotected != 1 || result.Plan.Summary.Protected != 0 || len(result.Plan.Routes) != 0 || len(result.Compatibility) != 0 {
		t.Fatalf("result=%+v", result)
	}
	if err := writeInspection(nil, manifest); err == nil {
		t.Fatal("nil inspection writer was accepted")
	}
}
