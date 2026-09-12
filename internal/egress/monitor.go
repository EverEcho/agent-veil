package egress

import "github.com/agentveil/agentveil/internal/domain"

type Connection struct {
	ProcessID         int
	ProcessName, Host string
	Port              uint16
	ThroughRouteID    string
	Blocked           bool
}
type Expected struct {
	ProcessID          int
	Host               string
	Port               uint16
	RouteID, SurfaceID string
}
type Assessment struct {
	Connection Connection
	Status     domain.CoverageStatus
	Risk       *domain.ProtectionRisk
}

func Assess(connections []Connection, expected []Expected) []Assessment {
	results := make([]Assessment, 0, len(connections))
	for _, connection := range connections {
		matched := false
		for _, route := range expected {
			if connection.ProcessID == route.ProcessID && connection.Host == route.Host && connection.Port == route.Port && connection.ThroughRouteID == route.RouteID {
				results = append(results, Assessment{Connection: connection, Status: domain.CoverageProtected})
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		status := domain.CoverageObserved
		if connection.Blocked {
			status = domain.CoverageUnprotected
		}
		risk := domain.ProtectionRisk{Code: domain.RiskUnsupportedCapability, Severity: domain.SeverityCritical, Message: "unexpected process egress does not match a protected route"}
		results = append(results, Assessment{Connection: connection, Status: status, Risk: &risk})
	}
	return results
}
