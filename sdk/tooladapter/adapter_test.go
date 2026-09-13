package tooladapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	native "github.com/agentveil/agentveil/sdk/native"
)

func TestBuildManifestEnumeratesMCPAndConservativeSpecialSurfaces(t *testing.T) {
	remote, err := RemoteMCP(RemoteMCPConfig{ID: "remote-mcp", Name: "Remote MCP", BaseURL: "https://mcp.example/v1/mcp", Protocol: native.ProtocolMCPStreamable, Auth: native.AuthStrategy{Type: native.AuthBearer, Source: "environment:MCP_TOKEN"}, Rewritable: true, Required: true, ConfigSource: "native:mcp"})
	if err != nil {
		t.Fatal(err)
	}
	local, err := LocalMCP("local-mcp", "Local MCP", "native:stdio", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := ObservedSpecial("browser", "Browser automation", "native:browser", InteractionBrowserAutomation, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(context.Background(), native.AgentInstance{ID: "custom-agent", Kind: "custom", Version: "1.0.0", Mode: native.ModeNative}, remote, local, browser)
	if err != nil || len(manifest.Surfaces) != 3 || !manifest.Surfaces[0].Rewritable || manifest.Surfaces[1].Protocol != native.ProtocolLocalStdio || manifest.Surfaces[2].Protocol != native.ProtocolUnknown || manifest.Surfaces[2].Rewritable || manifest.Surfaces[2].Metadata["interaction"] != string(InteractionBrowserAutomation) {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
}

func TestSDKRejectsUnsafeOrOverstatedSurfaces(t *testing.T) {
	if _, err := RemoteMCP(RemoteMCPConfig{ID: "mcp", Name: "MCP", BaseURL: "https://user:secret@mcp.example/mcp", Protocol: native.ProtocolMCPHTTP, Auth: native.AuthStrategy{Type: native.AuthPassthrough}, ConfigSource: "native:mcp"}); err == nil {
		t.Fatal("credential-bearing MCP URL was accepted")
	}
	if _, err := ObservedSpecial("tool", "Tool", "native:tool", Interaction("future"), true, nil); err == nil {
		t.Fatal("unknown Tool interaction was accepted")
	}
	if _, err := RemoteMCP(RemoteMCPConfig{ID: "mcp", Name: "MCP", BaseURL: "https://mcp.example/%2e%2e/mcp", Protocol: native.ProtocolMCPHTTP, Auth: native.AuthStrategy{Type: native.AuthPassthrough}, ConfigSource: "native:mcp"}); err == nil {
		t.Fatal("encoded MCP path traversal was accepted")
	}
	overstated := AdapterFunc(func(context.Context) ([]native.EgressSurface, error) {
		return []native.EgressSurface{{ID: "browser", Name: "Browser", Type: native.SurfaceBrowser, Protocol: native.ProtocolMCPHTTP, Upstream: &native.Upstream{Scheme: "https", Host: "browser.example", Port: 443}, Auth: native.AuthStrategy{Type: native.AuthPassthrough}, ConfigSource: "native:browser", Rewritable: true}}, nil
	})
	if _, err := BuildManifest(context.Background(), native.AgentInstance{ID: "agent", Kind: "custom", Mode: native.ModeNative}, overstated); err == nil {
		t.Fatal("overstated Browser protection was accepted")
	}
	if _, err := BuildManifest(context.Background(), native.AgentInstance{ID: "agent", Kind: "custom", Mode: native.ModeNative}, AdapterFunc(func(context.Context) ([]native.EgressSurface, error) { return nil, errors.New("secret discovery path") })); err == nil || strings.Contains(err.Error(), "secret discovery path") {
		t.Fatal("adapter failure was ignored")
	}
}

func TestSDKRejectsPanicsNilAdaptersAndDuplicateSurfaces(t *testing.T) {
	agent := native.AgentInstance{ID: "agent", Kind: "custom", Mode: native.ModeManaged}
	panicAdapter := AdapterFunc(func(context.Context) ([]native.EgressSurface, error) { panic("secret") })
	if manifest, err := BuildManifest(context.Background(), agent, panicAdapter); err == nil || len(manifest.Surfaces) != 0 {
		t.Fatalf("panic manifest=%+v err=%v", manifest, err)
	}
	if _, err := BuildManifest(context.Background(), agent, nil); err == nil {
		t.Fatal("nil adapter was accepted")
	}
	local, _ := LocalMCP("same", "Local", "native:stdio", false, nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildManifest(cancelled, agent, local); err == nil {
		t.Fatal("cancelled enumeration was accepted")
	}
	if _, err := BuildManifest(context.Background(), agent, local, local); err == nil {
		t.Fatal("duplicate Surface IDs were accepted")
	}
}

func TestStaticAdapterReturnsIndependentCopies(t *testing.T) {
	metadata := map[string]string{"source": "one"}
	adapter, err := LocalMCP("local", "Local", "native:stdio", false, metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata["source"] = "changed"
	first, _ := adapter.Surfaces(context.Background())
	first[0].Metadata["source"] = "mutated"
	second, _ := adapter.Surfaces(context.Background())
	if second[0].Metadata["source"] != "one" {
		t.Fatalf("adapter state was mutable: %+v", second)
	}
}
