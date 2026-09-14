package compatibility

import (
	"fmt"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/protocol"
)

type Verification string

const (
	VerificationLaunchSmoke   Verification = "launch_smoke"
	VerificationDiscoveryOnly Verification = "discovery_only"
)

type Record struct {
	Agent        string                 `json:"agent"`
	Version      string                 `json:"version"`
	Platform     string                 `json:"platform"`
	Mode         domain.IntegrationMode `json:"mode"`
	Surface      domain.SurfaceType     `json:"surface"`
	Protocol     domain.Protocol        `json:"protocol"`
	Auth         domain.AuthType        `json:"auth"`
	Coverage     domain.CoverageStatus  `json:"coverage"`
	Verification Verification           `json:"verification"`
	Notes        string                 `json:"notes"`
}

var records = mustValidate([]Record{
	{Agent: "codex", Version: "0.153.4", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "default OpenAI API-key and ChatGPT-login Responses routes passed protected launch smoke; custom providers excluded; live provider billing path not exercised"},
	{Agent: "codex", Version: "0.153.4", Platform: "darwin", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "default ChatGPT-login Responses route passed protected launch smoke on macOS; custom providers excluded; live provider billing path not exercised"},
	{Agent: "claude", Version: "2.1.220", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolAnthropic, Auth: domain.AuthAnthropicKey, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "API-key capability carrier and protected --help launch verified"},
	{Agent: "claude", Version: "2.1.220", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolAnthropic, Auth: domain.AuthPassthrough, Coverage: domain.CoverageObserved, Verification: VerificationDiscoveryOnly, Notes: "OAuth capability-header injection is not verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "same-runtime openai-codex primary route and protected launch verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelAuxiliary, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "same-runtime openai-codex compression, approval, and other auxiliary routes verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceVision, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "same-runtime openai-codex vision route verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelFallback, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "same-runtime openai-codex model and auxiliary fallback routes verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceSubAgent, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "same-runtime openai-codex delegation and delegation fallback routes verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceMCPHTTP, Protocol: domain.ProtocolMCPStreamable, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "remote MCP Streamable HTTP routing with capability headers verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceMCPHTTP, Protocol: domain.ProtocolMCPLegacySSE, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "legacy MCP SSE URL and capability-header launch rewrite plus stateful dual-endpoint provider boundary verified"},
	{Agent: "cursor", Version: "3.19.19", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Coverage: domain.CoverageUnprotected, Verification: VerificationDiscoveryOnly, Notes: "version detected; stable explicit routing adapter not verified"},
})

func Validate(candidate []Record) error {
	seen := make(map[string]struct{}, len(candidate))
	for index, record := range candidate {
		if strings.TrimSpace(record.Agent) == "" || strings.TrimSpace(record.Version) == "" || strings.TrimSpace(record.Platform) == "" || !record.Mode.Valid() || !record.Surface.Valid() || !record.Protocol.Valid() || record.Auth != "" && !record.Auth.Valid() || !record.Coverage.Valid() || strings.TrimSpace(record.Notes) == "" {
			return fmt.Errorf("compatibility record %d is incomplete", index)
		}
		if record.Verification != VerificationLaunchSmoke && record.Verification != VerificationDiscoveryOnly {
			return fmt.Errorf("compatibility record %d has unknown verification %q", index, record.Verification)
		}
		if record.Coverage == domain.CoverageProtected {
			if record.Surface == domain.SurfaceUnknown || !record.Auth.Valid() || record.Verification != VerificationLaunchSmoke || !protocol.SupportsContentProtection(record.Protocol) {
				return fmt.Errorf("compatibility record %d claims Protected without a fully implemented and launch-verified adapter", index)
			}
		}
		key := strings.Join([]string{record.Agent, record.Version, record.Platform, string(record.Mode), string(record.Surface), string(record.Protocol), string(record.Auth)}, "\x00")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("compatibility record %d duplicates an existing integration dimension", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func mustValidate(candidate []Record) []Record {
	if err := Validate(candidate); err != nil {
		panic(err)
	}
	return append([]Record(nil), candidate...)
}

func Current() []Record { return append([]Record(nil), records...) }

func ForAgent(agent, version, platform string) []Record {
	var result []Record
	for _, record := range records {
		if record.Agent == agent && record.Version == version && record.Platform == platform {
			result = append(result, record)
		}
	}
	return result
}

func VerifiedVersions(platform string) map[string]map[string]struct{} {
	result := map[string]map[string]struct{}{}
	for _, record := range records {
		if record.Platform != platform || record.Verification != VerificationLaunchSmoke || record.Coverage != domain.CoverageProtected {
			continue
		}
		if result[record.Agent] == nil {
			result[record.Agent] = map[string]struct{}{}
		}
		result[record.Agent][record.Version] = struct{}{}
	}
	return result
}
