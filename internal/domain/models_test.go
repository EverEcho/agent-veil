package domain

import (
	"encoding/json"
	"fmt"
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

func TestManifestCannotClaimCoverageWithoutSurfaces(t *testing.T) {
	manifest := AgentManifest{SchemaVersion: "v1", Agent: AgentInstance{ID: "a", Kind: "codex"}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("empty manifest was accepted")
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

func TestUpstreamValidatesBasePath(t *testing.T) {
	if err := (Upstream{Scheme: "https", Host: "api.example.com", Port: 443, Path: "/gateway/v1/"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", "//other.example/v1", "/safe/../admin", `/safe\admin`, "/safe?query"} {
		if err := (Upstream{Scheme: "https", Host: "api.example.com", Port: 443, Path: path}).Validate(); err == nil {
			t.Fatalf("unsafe base path %q accepted", path)
		}
	}
}

func TestNetworkSurfaceRequiresValidAuthAndNetworkRoute(t *testing.T) {
	surface := EgressSurface{ID: "primary", Name: "Primary", Type: SurfaceModelPrimary, Protocol: ProtocolOpenAIResponses, Upstream: &Upstream{Scheme: "https", Host: "api.example", Port: 443}, ConfigSource: "fixture", Rewritable: true}
	if err := surface.Validate(); err == nil {
		t.Fatal("network surface without explicit authentication was accepted")
	}
	surface.Auth = AuthStrategy{Type: AuthBearer}
	if err := surface.Validate(); err == nil {
		t.Fatal("non-passthrough authentication without source was accepted")
	}
	surface.Auth.Source = "environment:API_KEY"
	if err := surface.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, route := range []NetworkRoute{
		{Type: NetworkDirect, Endpoint: "http://127.0.0.1:8080"},
		{Type: NetworkSOCKS5, Endpoint: "http://127.0.0.1:1080"},
		{Type: NetworkHTTPProxy, Endpoint: "http://user:secret@127.0.0.1:8080"},
	} {
		if err := route.Validate(); err == nil {
			t.Fatalf("invalid route accepted: %+v", route)
		}
	}
	invalid := NetworkRoute{Type: NetworkHTTPProxy, Endpoint: "http://user:secret@127.0.0.1:8080"}
	surface.Network = &invalid
	if err := surface.Validate(); err == nil {
		t.Fatal("surface accepted an invalid bound network route")
	}
	local := EgressSurface{ID: "local", Name: "Local", Type: SurfaceMCPStdio, Protocol: ProtocolLocalStdio, Auth: AuthStrategy{Type: AuthPassthrough}, Network: &NetworkRoute{Type: NetworkDirect}, ConfigSource: "fixture"}
	if err := local.Validate(); err == nil {
		t.Fatal("local stdio accepted a network route")
	}
}

func TestPersistedIdentifiersAndCredentialSourcesRejectSensitiveText(t *testing.T) {
	base := EgressSurface{ID: "primary", Name: "Primary", Type: SurfaceModelPrimary, Protocol: ProtocolOpenAIResponses, Upstream: &Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: AuthStrategy{Type: AuthPassthrough, Source: "agent:managed-login"}, ConfigSource: "fixture", Rewritable: true}
	for _, id := range []string{"dev@example.com", "../primary", "line\nbreak", strings.Repeat("a", 129)} {
		surface := base
		surface.ID = id
		if err := surface.Validate(); err == nil {
			t.Fatalf("unsafe surface id accepted: %q", id)
		}
	}
	for _, source := range []string{"sk-secret-value", "environment:BAD/NAME", "literal:token", "agent:contains space"} {
		if err := (AuthStrategy{Type: AuthBearer, Source: source}).Validate(); err == nil {
			t.Fatalf("unsafe credential source accepted: %q", source)
		}
	}
	if err := (AuthStrategy{Type: AuthBearer, Source: "environment:PROVIDER_TOKEN"}).Validate(); err != nil {
		t.Fatal(err)
	}
	finding := Finding{RuleID: "pii.email", Category: "dev@example.com", Detector: "semantic", Severity: SeverityHigh, SuggestedAction: ActionBlock, Confidence: 1, Location: ContentLocation{Start: 0, End: 1}}
	if err := finding.Validate(1); err == nil {
		t.Fatal("sensitive finding category was accepted for audit")
	}
}

func TestManifestRejectsUnboundedOrInvalidAgentMetadata(t *testing.T) {
	surface := EgressSurface{ID: "primary", Name: "Primary", Type: SurfaceModelPrimary, Protocol: ProtocolOpenAIResponses, Upstream: &Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: AuthStrategy{Type: AuthPassthrough}, ConfigSource: "fixture", Rewritable: true}
	manifest := AgentManifest{SchemaVersion: "v1", Agent: AgentInstance{ID: "agent", Kind: "test", Mode: IntegrationMode("invalid")}, Surfaces: []EgressSurface{surface}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("invalid integration mode was accepted")
	}
	manifest.Agent.Mode = ModeNative
	manifest.Surfaces = make([]EgressSurface, MaxManifestSurfaces+1)
	for index := range manifest.Surfaces {
		candidate := surface
		candidate.ID = fmt.Sprintf("surface-%d", index)
		manifest.Surfaces[index] = candidate
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("unbounded surface set was accepted")
	}
	manifest.Surfaces = []EgressSurface{surface}
	manifest.Agent.Metadata = map[string]string{"unsafe/key": "value"}
	if err := manifest.Validate(); err == nil {
		t.Fatal("unsafe metadata key was accepted")
	}
	manifest.Agent.Metadata = map[string]string{"safe": strings.Repeat("x", maxReferenceBytes+1)}
	if err := manifest.Validate(); err == nil {
		t.Fatal("oversized metadata value was accepted")
	}
}
