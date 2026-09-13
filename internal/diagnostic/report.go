package diagnostic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
)

type Agent struct {
	Reference  string                 `json:"reference"`
	Kind       string                 `json:"kind"`
	Version    string                 `json:"version,omitempty"`
	State      string                 `json:"state"`
	Generation uint64                 `json:"generation"`
	Coverage   domain.CoverageSummary `json:"coverage"`
	ErrorCode  domain.ErrorCode       `json:"error_code,omitempty"`
}

type Event struct {
	Timestamp    time.Time        `json:"timestamp"`
	SessionRef   string           `json:"session_ref"`
	AgentRef     string           `json:"agent_ref"`
	SurfaceID    string           `json:"surface_id"`
	Protocol     domain.Protocol  `json:"protocol"`
	FindingTypes []string         `json:"finding_types,omitempty"`
	FindingCount int              `json:"finding_count"`
	Severity     domain.Severity  `json:"severity,omitempty"`
	Action       domain.Action    `json:"action"`
	LatencyMS    int64            `json:"latency_ms"`
	ErrorCode    domain.ErrorCode `json:"error_code,omitempty"`
}

type Report struct {
	SchemaVersion  string    `json:"schema_version"`
	GeneratedAt    time.Time `json:"generated_at"`
	CoreStatus     string    `json:"core_status"`
	ActiveSessions int       `json:"active_sessions"`
	Agents         []Agent   `json:"agents"`
	Events         []Event   `json:"events"`
}

func Build(scanner detector.ContentScanner, now time.Time, coreStatus string, activeSessions int, agents []Agent, events []domain.AuditEvent) (Report, error) {
	if scanner == nil || now.IsZero() || coreStatus == "" || activeSessions < 0 {
		return Report{}, domain.NewError(domain.ErrInvalidContract, "build diagnostics", "scanner, time, status, and session count are required")
	}
	result := Report{SchemaVersion: "v1", GeneratedAt: now.UTC(), CoreStatus: coreStatus, ActiveSessions: activeSessions, Agents: make([]Agent, len(agents)), Events: make([]Event, len(events))}
	for index, agent := range agents {
		agent.Reference = reference(agent.Reference)
		var err error
		if agent.Kind, err = sanitize(scanner, agent.Kind); err != nil {
			return Report{}, err
		}
		if agent.Version, err = sanitize(scanner, agent.Version); err != nil {
			return Report{}, err
		}
		result.Agents[index] = agent
	}
	for index, event := range events {
		summary := Event{Timestamp: event.Timestamp, SessionRef: reference(event.SessionID), AgentRef: reference(event.AgentID), Protocol: event.Protocol, FindingCount: event.FindingCount, Severity: event.Severity, Action: event.Action, LatencyMS: event.LatencyMS, ErrorCode: event.ErrorCode}
		var err error
		if summary.SurfaceID, err = sanitize(scanner, event.SurfaceID); err != nil {
			return Report{}, err
		}
		for _, findingType := range event.FindingTypes {
			value, err := sanitize(scanner, findingType)
			if err != nil {
				return Report{}, err
			}
			summary.FindingTypes = append(summary.FindingTypes, value)
		}
		result.Events[index] = summary
	}
	return result, nil
}

func Marshal(scanner detector.ContentScanner, report Report) ([]byte, error) {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	matches, err := detector.ScanContent(scanner, "/diagnostics", string(payload))
	if err != nil {
		return nil, domain.NewError(domain.ErrDetectorFailure, "marshal diagnostics", "secondary diagnostic scan failed")
	}
	if len(matches) != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "marshal diagnostics", "secondary diagnostic scan found sensitive content")
	}
	return append(payload, '\n'), nil
}

func sanitize(scanner detector.ContentScanner, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	matches, err := detector.ScanContent(scanner, "/diagnostics/field", value)
	if err != nil {
		return "", domain.NewError(domain.ErrDetectorFailure, "sanitize diagnostics", "diagnostic field scan failed")
	}
	if len(matches) != 0 {
		return "[redacted]", nil
	}
	return value, nil
}

func reference(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:16])
}
