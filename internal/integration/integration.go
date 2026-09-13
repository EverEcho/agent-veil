package integration

import (
	"net"
	"net/url"
	"path/filepath"
	"strconv"
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
	Network              *domain.NetworkRoute
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
	versions := i.VerifiedVersions[config.Kind]
	_, verified := versions[config.Version]
	if !verified {
		for _, slot := range append(append([]Slot(nil), config.Slots...), config.Observed...) {
			if slot.Rewritable {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "inspect agent", "unverified agent version cannot claim a rewritable surface")
			}
		}
	}
	manifest := domain.AgentManifest{SchemaVersion: "v1", GeneratedAt: time.Now().UTC(), Agent: domain.AgentInstance{ID: config.AgentID, Kind: config.Kind, Version: config.Version, Executable: config.Executable, Mode: config.Mode}}
	if !verified {
		manifest.Agent.Metadata = map[string]string{"compatibility": "unverified"}
	}
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
		var network *domain.NetworkRoute
		if slot.Network != nil {
			copy := *slot.Network
			network = &copy
		}
		manifest.Surfaces = append(manifest.Surfaces, domain.EgressSurface{ID: slot.ID, Name: slot.Name, Type: slot.Type, Protocol: slot.Protocol, Upstream: upstream, Auth: auth, Network: network, ConfigSource: config.ConfigSource, Rewritable: slot.Rewritable, Required: slot.Required, Metadata: cloneMetadata(slot.Metadata)})
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
	cleanup     func() error
}

// Cleanup releases temporary launch resources. It is safe to call more than
// once and is a no-op for launch plans without external resources.
func (p *LaunchPlan) Cleanup() error {
	if p == nil || p.cleanup == nil {
		return nil
	}
	return p.cleanup()
}

func PrepareLaunch(agent domain.AgentInstance, args []string, coreEndpoint, sessionID, parentID, routeToken string) (LaunchPlan, error) {
	if agent.Mode != domain.ModeLaunch {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare launch", "agent is not configured for launch mode")
	}
	if !filepath.IsAbs(agent.Executable) || strings.ContainsRune(agent.Executable, 0) {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare launch", "agent executable must be an absolute path")
	}
	if err := validateCoreEndpoint(coreEndpoint); err != nil {
		return LaunchPlan{}, err
	}
	if !validCapabilityID(sessionID) || parentID != "" && !validCapabilityID(parentID) || !validRouteToken(routeToken) {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare launch", "session identity or route capability is invalid")
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

// PrepareHermesLaunch binds an already rewritten Hermes configuration to a
// private temporary HERMES_HOME. The caller must defer Cleanup immediately
// after a successful return.
func PrepareHermesLaunch(agent domain.AgentInstance, args []string, coreEndpoint, sessionID, parentID, routeToken, sourceHome string, config []byte, runtimeEnvironment map[string]string) (LaunchPlan, error) {
	if agent.Kind != "hermes" {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare hermes launch", "agent kind is not Hermes")
	}
	plan, err := PrepareLaunch(agent, args, coreEndpoint, sessionID, parentID, routeToken)
	if err != nil {
		return LaunchPlan{}, err
	}
	temporaryHome, cleanup, err := prepareHermesHome(sourceHome, config, runtimeEnvironment)
	if err != nil {
		return LaunchPlan{}, err
	}
	plan.Environment["HERMES_HOME"] = temporaryHome
	for key, value := range runtimeEnvironment {
		plan.Environment[key] = value
	}
	plan.cleanup = cleanup
	return plan, nil
}

func validateCoreEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return domain.NewError(domain.ErrInvalidContract, "prepare launch", "Core endpoint is invalid")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	ip := net.ParseIP(host)
	if err != nil || portErr != nil || portNumber == 0 || ip == nil || !ip.IsLoopback() {
		return domain.NewError(domain.ErrInvalidContract, "prepare launch", "Core endpoint must use a loopback address and explicit port")
	}
	return nil
}

func validCapabilityID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validRouteToken(value string) bool {
	if len(value) < 32 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_~=+./", character) {
			continue
		}
		return false
	}
	return true
}
