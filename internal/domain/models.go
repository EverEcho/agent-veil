package domain

import "time"

type AgentInstance struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Version    string            `json:"version"`
	Executable string            `json:"executable,omitempty"`
	Mode       IntegrationMode   `json:"mode"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Upstream struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	Path   string `json:"path,omitempty"`
}

type AuthStrategy struct {
	Type   AuthType `json:"type"`
	Source string   `json:"source,omitempty"`
}

type NetworkRoute struct {
	Type     NetworkType `json:"type"`
	Endpoint string      `json:"endpoint,omitempty"`
}

type EgressSurface struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         SurfaceType       `json:"type"`
	Protocol     Protocol          `json:"protocol"`
	Upstream     *Upstream         `json:"upstream,omitempty"`
	Auth         AuthStrategy      `json:"auth"`
	Network      *NetworkRoute     `json:"network,omitempty"`
	ConfigSource string            `json:"config_source"`
	Rewritable   bool              `json:"rewritable"`
	Required     bool              `json:"required"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type AgentManifest struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Agent         AgentInstance   `json:"agent"`
	Surfaces      []EgressSurface `json:"surfaces"`
}

type ProtectedRoute struct {
	ID             string       `json:"id"`
	SurfaceID      string       `json:"surface_id"`
	Protocol       Protocol     `json:"protocol"`
	Upstream       Upstream     `json:"upstream"`
	Auth           AuthStrategy `json:"auth"`
	Network        NetworkRoute `json:"network"`
	PolicyID       string       `json:"policy_id"`
	RequiresStream bool         `json:"requires_stream"`
}

type RiskCode string

const (
	RiskUnknownSurface          RiskCode = "UNKNOWN_SURFACE"
	RiskUnknownProtocol         RiskCode = "UNKNOWN_PROTOCOL"
	RiskNotRewritable           RiskCode = "SURFACE_NOT_REWRITABLE"
	RiskRequestOnly             RiskCode = "REQUEST_ONLY_PROTECTION"
	RiskStreamUnsupported       RiskCode = "STREAM_UNSUPPORTED"
	RiskObservedOnly            RiskCode = "OBSERVED_ONLY"
	RiskUnsupportedCapability   RiskCode = "UNSUPPORTED_CAPABILITY"
	RiskContentModifierAfterDLP RiskCode = "CONTENT_MODIFIER_AFTER_DLP"
	RiskUnexpectedEgress        RiskCode = "UNEXPECTED_EGRESS"
)

type ProtectionRisk struct {
	SurfaceID string   `json:"surface_id"`
	Code      RiskCode `json:"code"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
}

type SurfaceCoverage struct {
	SurfaceID string         `json:"surface_id"`
	Status    CoverageStatus `json:"status"`
	Reason    string         `json:"reason"`
	RouteID   string         `json:"route_id,omitempty"`
}

type CoverageSummary struct {
	Total       int `json:"total"`
	Protected   int `json:"protected"`
	Local       int `json:"local"`
	Partial     int `json:"partial"`
	Observed    int `json:"observed"`
	Unprotected int `json:"unprotected"`
}

type ProtectionPlan struct {
	SchemaVersion string            `json:"schema_version"`
	ManifestID    string            `json:"manifest_id"`
	Routes        []ProtectedRoute  `json:"routes"`
	Coverage      []SurfaceCoverage `json:"coverage"`
	Risks         []ProtectionRisk  `json:"risks"`
	Summary       CoverageSummary   `json:"summary"`
}

type ProtectionSession struct {
	ID              string    `json:"id"`
	ParentSessionID string    `json:"parent_session_id,omitempty"`
	CoreEndpoint    string    `json:"core_endpoint"`
	StartedAt       time.Time `json:"started_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	RouteIDs        []string  `json:"route_ids"`
	secret          []byte
}

func NewProtectionSession(id, parentID, endpoint string, startedAt, expiresAt time.Time, routeIDs []string, secret []byte) ProtectionSession {
	return ProtectionSession{ID: id, ParentSessionID: parentID, CoreEndpoint: endpoint,
		StartedAt: startedAt, ExpiresAt: expiresAt, RouteIDs: append([]string(nil), routeIDs...),
		secret: append([]byte(nil), secret...)}
}

func (s ProtectionSession) SessionSecret() []byte { return append([]byte(nil), s.secret...) }

// DestroySecret clears the in-memory session capability. Callers must not use a
// ProtectionSession after destruction.
func (s *ProtectionSession) DestroySecret() {
	for i := range s.secret {
		s.secret[i] = 0
	}
	s.secret = nil
}

type ContentLocation struct {
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type Finding struct {
	RuleID          string          `json:"rule_id"`
	Category        string          `json:"category"`
	Severity        Severity        `json:"severity"`
	Location        ContentLocation `json:"location"`
	Confidence      float64         `json:"confidence"`
	Detector        string          `json:"detector"`
	SuggestedAction Action          `json:"suggested_action"`
}

type AuditEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	SessionID    string    `json:"session_id"`
	AgentID      string    `json:"agent_id"`
	SurfaceID    string    `json:"surface_id"`
	Protocol     Protocol  `json:"protocol"`
	FindingTypes []string  `json:"finding_types,omitempty"`
	FindingCount int       `json:"finding_count"`
	Severity     Severity  `json:"severity,omitempty"`
	Action       Action    `json:"action"`
	LatencyMS    int64     `json:"latency_ms"`
	ErrorCode    ErrorCode `json:"error_code,omitempty"`
	WorkspaceRef string    `json:"workspace_ref,omitempty"`
}
