package tooladapter_test

import (
	"context"
	"fmt"

	native "github.com/agentveil/agentveil/sdk/native"
	"github.com/agentveil/agentveil/sdk/tooladapter"
)

func ExampleBuildManifest() {
	mcp, _ := tooladapter.RemoteMCP(tooladapter.RemoteMCPConfig{ID: "search", Name: "Search MCP", BaseURL: "https://mcp.example/mcp", Protocol: native.ProtocolMCPStreamable, Auth: native.AuthStrategy{Type: native.AuthBearer, Source: "environment:MCP_TOKEN"}, ConfigSource: "native:tools", Rewritable: true, Required: true})
	manifest, err := tooladapter.BuildManifest(context.Background(), native.AgentInstance{ID: "example", Kind: "example", Version: "1.0.0", Mode: native.ModeNative}, mcp)
	fmt.Println(err == nil, manifest.Surfaces[0].Protocol)
	// Output: true mcp_streamable_http
}
