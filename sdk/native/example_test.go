package native_test

import (
	"testing"

	"github.com/agentveil/agentveil/sdk/native"
)

func TestPublicManifestTypesRequireNoInternalImports(t *testing.T) {
	manifest := native.AgentManifest{
		SchemaVersion: "v1",
		Agent:         native.AgentInstance{ID: "example", Kind: "custom-agent", Version: "1.0.0", Mode: native.ModeNative},
		Surfaces: []native.EgressSurface{{
			ID:           "primary",
			Name:         "Primary",
			Type:         native.SurfaceModelPrimary,
			Protocol:     native.ProtocolOpenAIResponses,
			Upstream:     &native.Upstream{Scheme: "https", Host: "api.example", Port: 443},
			Auth:         native.AuthStrategy{Type: native.AuthPassthrough},
			Network:      &native.NetworkRoute{Type: native.NetworkDirect},
			ConfigSource: "native-sdk",
			Rewritable:   true,
			Required:     true,
		}},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicNestedRouteClientConstructor(t *testing.T) {
	client, err := native.NewRouteClient("http://127.0.0.1:43123", "session-0123456789abcdef", "route-primary-g1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil)
	if err != nil || client == nil {
		t.Fatalf("public route client construction failed: %v", err)
	}
}
