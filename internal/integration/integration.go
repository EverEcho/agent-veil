package integration

import (
	"net/url"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type Slot struct {
	ID, Name             string
	Type                 domain.SurfaceType
	Protocol             domain.Protocol
	BaseURL              string
	Auth                 domain.AuthStrategy
	Metadata             map[string]string
	Rewritable, Required bool
}

type Config struct {
	AgentID, Kind, Version, Executable, ConfigSource string
	Mode                                             domain.IntegrationMode
	Slots                                            []Slot
	LocalMCP                                         []string
	Observed                                         []Slot
}

type Inspector struct {
	VerifiedVersions map[string]map[string]struct{}
}

func (i Inspector) Inspect(config Config) (domain.AgentManifest, error) {
	versions, ok := i.VerifiedVersions[config.Kind]
	if !ok {
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "inspect agent", "agent kind has no compatibility record")
	}
	if _, ok := versions[config.Version]; !ok {
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "inspect agent", "agent version is not verified")
	}
	manifest := domain.AgentManifest{SchemaVersion: "v1", GeneratedAt: time.Now().UTC(), Agent: domain.AgentInstance{ID: config.AgentID, Kind: config.Kind, Version: config.Version, Executable: config.Executable, Mode: config.Mode}}
	all := append(append([]Slot(nil), config.Slots...), config.Observed...)
	for _, slot := range all {
		var upstream *domain.Upstream
		if slot.BaseURL != "" {
			parsed, err := url.Parse(slot.BaseURL)
			if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "inspect agent", "slot upstream is invalid")
			}
			port := uint16(443)
			if parsed.Scheme == "http" {
				port = 80
			}
			if parsed.Port() != "" {
				value := 0
				for _, char := range parsed.Port() {
					if char < '0' || char > '9' {
						return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "inspect agent", "slot port is invalid")
					}
					value = value*10 + int(char-'0')
				}
				if value < 1 || value > 65535 {
					return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "inspect agent", "slot port is invalid")
				}
				port = uint16(value)
			}
			upstream = &domain.Upstream{Scheme: parsed.Scheme, Host: parsed.Hostname(), Port: port, Path: parsed.Path}
		}
		auth := slot.Auth
		if auth.Type == "" {
			auth.Type = domain.AuthPassthrough
		}
		manifest.Surfaces = append(manifest.Surfaces, domain.EgressSurface{ID: slot.ID, Name: slot.Name, Type: slot.Type, Protocol: slot.Protocol, Upstream: upstream, Auth: auth, ConfigSource: config.ConfigSource, Rewritable: slot.Rewritable, Required: slot.Required, Metadata: cloneMetadata(slot.Metadata)})
	}
	for _, name := range config.LocalMCP {
		id := "mcp-" + strings.NewReplacer(" ", "-", "/", "-").Replace(strings.ToLower(name))
		manifest.Surfaces = append(manifest.Surfaces, domain.EgressSurface{ID: id, Name: name, Type: domain.SurfaceMCPStdio, Protocol: domain.ProtocolLocalStdio, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, ConfigSource: config.ConfigSource})
	}
	if err := manifest.Validate(); err != nil {
		return domain.AgentManifest{}, err
	}
	return manifest, nil
}

func cloneMetadata(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

type LaunchPlan struct {
	Executable  string
	Args        []string
	Environment map[string]string
	Temporary   bool
}

func PrepareLaunch(agent domain.AgentInstance, args []string, coreEndpoint, sessionID, parentID, routeToken string) (LaunchPlan, error) {
	if agent.Mode != domain.ModeLaunch {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare launch", "agent is not configured for launch mode")
	}
	for _, arg := range args {
		lower := strings.ToLower(arg)
		for _, conflict := range []string{"base-url", "base_url", "provider", "websocket", "compression"} {
			if strings.Contains(lower, conflict) {
				return LaunchPlan{}, domain.NewError(domain.ErrPolicyBlocked, "prepare launch", "launch argument can override protected routing")
			}
		}
	}
	environment := map[string]string{"VEIL_SESSION_ID": sessionID, "VEIL_PROTECTION_TOKEN": routeToken, "VEIL_CORE_ENDPOINT": coreEndpoint}
	if parentID != "" {
		environment["VEIL_PARENT_SESSION"] = parentID
	}
	switch agent.Kind {
	case "codex":
		environment["OPENAI_BASE_URL"] = coreEndpoint
		environment["CODEX_DISABLE_WEBSOCKET"] = "1"
		environment["CODEX_DISABLE_COMPRESSION"] = "1"
	case "claude":
		environment["ANTHROPIC_BASE_URL"] = coreEndpoint
	default:
		environment["AI_BASE_URL"] = coreEndpoint
	}
	return LaunchPlan{Executable: agent.Executable, Args: append([]string(nil), args...), Environment: environment, Temporary: true}, nil
}
