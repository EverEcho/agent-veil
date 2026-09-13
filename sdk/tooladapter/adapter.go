// Package tooladapter provides a declarative SDK for Native and Managed hosts
// to enumerate MCP, Browser, and Tool egress surfaces. It deliberately does not
// expose detection or rewriting hooks: content protection remains in Core.
package tooladapter

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	native "github.com/agentveil/agentveil/sdk/native"
)

type Adapter interface {
	Surfaces(context.Context) ([]native.EgressSurface, error)
}

type AdapterFunc func(context.Context) ([]native.EgressSurface, error)

func (f AdapterFunc) Surfaces(ctx context.Context) ([]native.EgressSurface, error) {
	return f(ctx)
}

type RemoteMCPConfig struct {
	ID           string
	Name         string
	BaseURL      string
	Protocol     native.Protocol
	Auth         native.AuthStrategy
	Network      *native.NetworkRoute
	ConfigSource string
	Rewritable   bool
	Required     bool
	Metadata     map[string]string
}

type Interaction string

const (
	InteractionBrowserAutomation Interaction = "browser_automation"
	InteractionOAuth             Interaction = "oauth"
	InteractionFileUpload        Interaction = "file_upload"
	InteractionFileDownload      Interaction = "file_download"
	InteractionWebSocket         Interaction = "websocket"
	InteractionToolHTTP          Interaction = "tool_http"
)

type staticAdapter struct {
	surfaces []native.EgressSurface
}

func (a staticAdapter) Surfaces(context.Context) ([]native.EgressSurface, error) {
	return cloneSurfaces(a.surfaces), nil
}

func RemoteMCP(config RemoteMCPConfig) (Adapter, error) {
	if config.Protocol != native.ProtocolMCPHTTP && config.Protocol != native.ProtocolMCPStreamable {
		return nil, fmt.Errorf("remote MCP requires an implemented MCP HTTP protocol")
	}
	upstream, err := parseUpstream(config.BaseURL)
	if err != nil {
		return nil, err
	}
	surface := native.EgressSurface{ID: config.ID, Name: config.Name, Type: native.SurfaceMCPHTTP, Protocol: config.Protocol, Upstream: &upstream, Auth: config.Auth, Network: cloneNetwork(config.Network), ConfigSource: config.ConfigSource, Rewritable: config.Rewritable, Required: config.Required, Metadata: cloneMetadata(config.Metadata)}
	if err := surface.Validate(); err != nil {
		return nil, err
	}
	return staticAdapter{surfaces: []native.EgressSurface{surface}}, nil
}

func LocalMCP(id, name, configSource string, required bool, metadata map[string]string) (Adapter, error) {
	surface := native.EgressSurface{ID: id, Name: name, Type: native.SurfaceMCPStdio, Protocol: native.ProtocolLocalStdio, Auth: native.AuthStrategy{Type: native.AuthPassthrough}, ConfigSource: configSource, Required: required, Metadata: cloneMetadata(metadata)}
	if err := surface.Validate(); err != nil {
		return nil, err
	}
	return staticAdapter{surfaces: []native.EgressSurface{surface}}, nil
}

// ObservedSpecial declares a complex interaction conservatively. The returned
// Surface is always ProtocolUnknown and non-rewritable, so a host cannot use
// this convenience constructor to overstate Browser, OAuth, file, WebSocket,
// or generic Tool HTTP coverage.
func ObservedSpecial(id, name, configSource string, interaction Interaction, required bool, metadata map[string]string) (Adapter, error) {
	if !interaction.Valid() {
		return nil, fmt.Errorf("tool interaction is invalid")
	}
	surfaceType := native.SurfaceToolHTTP
	if interaction == InteractionBrowserAutomation {
		surfaceType = native.SurfaceBrowser
	}
	metadata = cloneMetadata(metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["interaction"] = string(interaction)
	surface := native.EgressSurface{ID: id, Name: name, Type: surfaceType, Protocol: native.ProtocolUnknown, ConfigSource: configSource, Required: required, Metadata: metadata}
	if err := surface.Validate(); err != nil {
		return nil, err
	}
	return staticAdapter{surfaces: []native.EgressSurface{surface}}, nil
}

func (i Interaction) Valid() bool {
	switch i {
	case InteractionBrowserAutomation, InteractionOAuth, InteractionFileUpload, InteractionFileDownload, InteractionWebSocket, InteractionToolHTTP:
		return true
	default:
		return false
	}
}

func BuildManifest(ctx context.Context, agent native.AgentInstance, adapters ...Adapter) (manifest native.AgentManifest, err error) {
	if ctx == nil || (agent.Mode != native.ModeNative && agent.Mode != native.ModeManaged) || len(adapters) == 0 {
		return native.AgentManifest{}, fmt.Errorf("context, Native/Managed agent, and adapters are required")
	}
	defer func() {
		if recover() != nil {
			manifest = native.AgentManifest{}
			err = fmt.Errorf("tool Surface Adapter panicked")
		}
	}()
	agent.Metadata = cloneMetadata(agent.Metadata)
	manifest = native.AgentManifest{SchemaVersion: "v1", GeneratedAt: time.Now().UTC(), Agent: agent, Surfaces: []native.EgressSurface{}}
	for _, adapter := range adapters {
		if err := ctx.Err(); err != nil {
			return native.AgentManifest{}, fmt.Errorf("enumerate tool Surfaces: context ended")
		}
		if adapter == nil {
			return native.AgentManifest{}, fmt.Errorf("tool Surface Adapter is nil")
		}
		surfaces, adapterErr := adapter.Surfaces(ctx)
		if adapterErr != nil {
			return native.AgentManifest{}, fmt.Errorf("enumerate tool Surfaces: adapter failed")
		}
		if len(surfaces) == 0 || len(manifest.Surfaces)+len(surfaces) > 256 {
			return native.AgentManifest{}, fmt.Errorf("tool Surface count is outside its limit")
		}
		for _, surface := range surfaces {
			if err := validateToolSurface(surface); err != nil {
				return native.AgentManifest{}, err
			}
		}
		manifest.Surfaces = append(manifest.Surfaces, cloneSurfaces(surfaces)...)
	}
	if err := manifest.Validate(); err != nil {
		return native.AgentManifest{}, err
	}
	return manifest, nil
}

func validateToolSurface(surface native.EgressSurface) error {
	if err := surface.Validate(); err != nil {
		return err
	}
	switch surface.Type {
	case native.SurfaceMCPHTTP:
		if surface.Protocol != native.ProtocolMCPHTTP && surface.Protocol != native.ProtocolMCPStreamable {
			return fmt.Errorf("remote MCP Surface protocol is invalid")
		}
	case native.SurfaceMCPStdio:
		if surface.Protocol != native.ProtocolLocalStdio || surface.Rewritable || surface.Upstream != nil || surface.Network != nil {
			return fmt.Errorf("local MCP Surface semantics are invalid")
		}
	case native.SurfaceBrowser, native.SurfaceToolHTTP:
		if surface.Protocol != native.ProtocolUnknown || surface.Rewritable {
			return fmt.Errorf("special Tool Surface must remain unknown and non-rewritable")
		}
	default:
		return fmt.Errorf("adapter returned a non-tool Surface")
	}
	return nil
}

func parseUpstream(value string) (native.Upstream, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" || parsed.RawPath != "" {
		return native.Upstream{}, fmt.Errorf("remote MCP base URL is invalid")
	}
	port := uint16(443)
	if parsed.Scheme == "http" {
		port = 80
	}
	if parsed.Port() != "" {
		parsedPort, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || parsedPort == 0 {
			return native.Upstream{}, fmt.Errorf("remote MCP port is invalid")
		}
		port = uint16(parsedPort)
	}
	upstream := native.Upstream{Scheme: parsed.Scheme, Host: parsed.Hostname(), Port: port, Path: strings.TrimSuffix(parsed.Path, "/")}
	probe := native.EgressSurface{ID: "probe", Name: "Probe", Type: native.SurfaceMCPHTTP, Protocol: native.ProtocolMCPHTTP, Upstream: &upstream, Auth: native.AuthStrategy{Type: native.AuthPassthrough}, ConfigSource: "adapter", Rewritable: true}
	if err := probe.Validate(); err != nil {
		return native.Upstream{}, err
	}
	return upstream, nil
}

func cloneSurfaces(input []native.EgressSurface) []native.EgressSurface {
	result := make([]native.EgressSurface, len(input))
	for index, surface := range input {
		result[index] = surface
		result[index].Metadata = cloneMetadata(surface.Metadata)
		if surface.Upstream != nil {
			upstream := *surface.Upstream
			result[index].Upstream = &upstream
		}
		result[index].Network = cloneNetwork(surface.Network)
	}
	return result
}

func cloneNetwork(input *native.NetworkRoute) *native.NetworkRoute {
	if input == nil {
		return nil
	}
	result := *input
	return &result
}

func cloneMetadata(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
