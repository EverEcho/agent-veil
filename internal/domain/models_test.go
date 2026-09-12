package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestManifestExpressesAllRequiredSurfaceTypes(t *testing.T) {
	types := []SurfaceType{SurfaceModelPrimary, SurfaceModelAuxiliary, SurfaceModelFallback,
		SurfaceVision, SurfaceEmbedding, SurfaceImage, SurfaceAudio, SurfaceMCPHTTP,
		SurfaceMCPStdio, SurfaceToolHTTP, SurfaceBrowser, SurfaceSubAgent, SurfaceACP, SurfaceUnknown}
	for _, surfaceType := range types {
		if !surfaceType.Valid() {
			t.Fatalf("documented surface type %q is invalid", surfaceType)
		}
	}
}

func TestManifestRejectsDuplicateSurfaceID(t *testing.T) {
	surface := EgressSurface{ID: "primary", Name: "Primary", Type: SurfaceModelPrimary,
		Protocol: ProtocolOpenAIResponses, Upstream: &Upstream{Scheme: "https", Host: "api.openai.com", Port: 443},
		Auth: AuthStrategy{Type: AuthPassthrough}, ConfigSource: "fixture", Rewritable: true, Required: true}
	manifest := AgentManifest{SchemaVersion: "v1", GeneratedAt: time.Now(), Agent: AgentInstance{ID: "a", Kind: "codex"}, Surfaces: []EgressSurface{surface, surface}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected duplicate surface id to fail")
	}
}

func TestSessionSecretIsNeverSerialized(t *testing.T) {
	session := NewProtectionSession("s", "", "http://127.0.0.1:1234", time.Now(), time.Now().Add(time.Hour), []string{"r"}, []byte(strings.Repeat("x", 32)))
	payload, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), strings.Repeat("x", 32)) || strings.Contains(string(payload), "secret") {
		t.Fatalf("session secret leaked into serialized form: %s", payload)
	}
}

func TestRemotePlaintextUpstreamFailsClosed(t *testing.T) {
	if err := (Upstream{Scheme: "http", Host: "api.example.com", Port: 80}).Validate(); err == nil {
		t.Fatal("expected remote HTTP upstream to be rejected")
	}
	if err := (Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}).Validate(); err != nil {
		t.Fatalf("expected explicit loopback HTTP to be allowed: %v", err)
	}
}
