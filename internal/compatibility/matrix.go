package compatibility

import "github.com/agentveil/agentveil/internal/domain"

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

var records = []Record{
	{Agent: "codex", Version: "0.153.4", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, Auth: domain.AuthPassthrough, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "protected --help launch verified; live provider billing path not exercised"},
	{Agent: "claude", Version: "2.1.220", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolAnthropic, Auth: domain.AuthAnthropicKey, Coverage: domain.CoverageProtected, Verification: VerificationLaunchSmoke, Notes: "API-key capability carrier and protected --help launch verified"},
	{Agent: "claude", Version: "2.1.220", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceModelPrimary, Protocol: domain.ProtocolAnthropic, Auth: domain.AuthPassthrough, Coverage: domain.CoverageObserved, Verification: VerificationDiscoveryOnly, Notes: "OAuth capability-header injection is not verified"},
	{Agent: "hermes", Version: "0.20.6", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Coverage: domain.CoverageUnprotected, Verification: VerificationDiscoveryOnly, Notes: "version detected; versioned configuration adapter not implemented"},
	{Agent: "cursor", Version: "3.19.19", Platform: "linux", Mode: domain.ModeLaunch, Surface: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Coverage: domain.CoverageUnprotected, Verification: VerificationDiscoveryOnly, Notes: "version detected; stable explicit routing adapter not verified"},
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
		if record.Platform != platform {
			continue
		}
		if result[record.Agent] == nil {
			result[record.Agent] = map[string]struct{}{}
		}
		result[record.Agent][record.Version] = struct{}{}
	}
	return result
}
