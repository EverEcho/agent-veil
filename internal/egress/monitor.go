package egress

import (
	"net"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type Status string
type Transport string

const (
	StatusContentProtected Status    = "content_protected"
	StatusObserved         Status    = "observed"
	StatusBlocked          Status    = "blocked"
	TransportTCP           Transport = "tcp"
	TransportUDP           Transport = "udp"
)

type Connection struct {
	ProcessIdentity
	ProcessName    string    `json:"process_name,omitempty"`
	Transport      Transport `json:"transport,omitempty"`
	Host           string    `json:"host"`
	Port           uint16    `json:"port"`
	ThroughRouteID string    `json:"through_route_id,omitempty"`
	Blocked        bool      `json:"blocked"`
}
type Expected struct {
	ProcessIdentity
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	RouteID   string `json:"route_id"`
	SurfaceID string `json:"surface_id"`
}
type Assessment struct {
	Connection Connection             `json:"connection"`
	Status     Status                 `json:"status"`
	SurfaceID  string                 `json:"surface_id,omitempty"`
	Risk       *domain.ProtectionRisk `json:"risk,omitempty"`
}

func Assess(connections []Connection, expected []Expected) []Assessment {
	results := make([]Assessment, 0, len(connections))
	for _, connection := range connections {
		var matched *Expected
		for _, route := range expected {
			if validExpected(route) && connection.ProcessIdentity == route.ProcessIdentity && canonicalHost(connection.Host) == canonicalHost(route.Host) && connection.Port == route.Port && connection.ThroughRouteID == route.RouteID {
				copy := route
				matched = &copy
				break
			}
		}
		if matched != nil && !connection.Blocked {
			results = append(results, Assessment{Connection: connection, Status: StatusContentProtected, SurfaceID: matched.SurfaceID})
			continue
		}
		status := StatusObserved
		if connection.Blocked {
			status = StatusBlocked
		}
		message := "unexpected process egress was observed outside protected routes"
		if connection.Blocked {
			message = "process egress was blocked before bypassing protected routes"
		}
		surfaceID := ""
		if matched != nil {
			surfaceID = matched.SurfaceID
		}
		risk := domain.ProtectionRisk{SurfaceID: surfaceID, Code: domain.RiskUnexpectedEgress, Severity: domain.SeverityCritical, Message: message}
		results = append(results, Assessment{Connection: connection, Status: status, SurfaceID: surfaceID, Risk: &risk})
	}
	return results
}

func validExpected(route Expected) bool {
	return validProcessIdentity(route.ProcessIdentity) && canonicalHost(route.Host) != "" && route.Port > 0 && route.RouteID != "" && route.SurfaceID != ""
}

func canonicalHost(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	return value
}
