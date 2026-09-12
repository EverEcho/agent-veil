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
	StatusLocal            Status    = "local"
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
	Transport Transport `json:"transport"`
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	RouteID   string    `json:"route_id"`
	SurfaceID string    `json:"surface_id"`
}

// LocalEndpoint identifies an exact loopback hop that is allowed to stay on
// the device. A match only establishes locality; it does not prove that the
// connection's content passed through a protected route.
type LocalEndpoint struct {
	Transport Transport `json:"transport"`
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
}
type Assessment struct {
	Connection Connection             `json:"connection"`
	Status     Status                 `json:"status"`
	SurfaceID  string                 `json:"surface_id,omitempty"`
	Risk       *domain.ProtectionRisk `json:"risk,omitempty"`
}

const (
	MaxExpectedRoutes = 256
	MaxLocalEndpoints = 256
)

type expectedKey struct {
	ProcessIdentity
	Transport Transport
	Host      string
	Port      uint16
	RouteID   string
}

type localKey struct {
	Transport Transport
	Host      string
	Port      uint16
}

func Assess(connections []Connection, expected []Expected) []Assessment {
	return AssessWithLocalEndpoints(connections, expected, nil)
}

func AssessWithLocalEndpoints(connections []Connection, expected []Expected, localEndpoints []LocalEndpoint) []Assessment {
	expectedIndex := make(map[expectedKey]Expected, len(expected))
	for _, route := range expected {
		if !validExpected(route) {
			continue
		}
		key := expectedKey{ProcessIdentity: route.ProcessIdentity, Transport: route.Transport, Host: canonicalHost(route.Host), Port: route.Port, RouteID: route.RouteID}
		if _, exists := expectedIndex[key]; !exists {
			expectedIndex[key] = route
		}
	}
	localIndex := make(map[localKey]struct{}, len(localEndpoints))
	for _, endpoint := range localEndpoints {
		if validLocalEndpoint(endpoint) {
			localIndex[localKey{Transport: endpoint.Transport, Host: canonicalHost(endpoint.Host), Port: endpoint.Port}] = struct{}{}
		}
	}
	results := make([]Assessment, 0, len(connections))
	for _, connection := range connections {
		var matched *Expected
		key := expectedKey{ProcessIdentity: connection.ProcessIdentity, Transport: connection.Transport, Host: canonicalHost(connection.Host), Port: connection.Port, RouteID: connection.ThroughRouteID}
		if route, ok := expectedIndex[key]; ok {
			copy := route
			matched = &copy
		}
		if matched != nil && !connection.Blocked {
			results = append(results, Assessment{Connection: connection, Status: StatusContentProtected, SurfaceID: matched.SurfaceID})
			continue
		}
		_, local := localIndex[localKey{Transport: connection.Transport, Host: canonicalHost(connection.Host), Port: connection.Port}]
		if !connection.Blocked && local {
			results = append(results, Assessment{Connection: connection, Status: StatusLocal})
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

func validLocalEndpoint(endpoint LocalEndpoint) bool {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(endpoint.Host), "[]"))
	return validTransport(endpoint.Transport) && ip != nil && ip.IsLoopback() && endpoint.Port > 0
}

func validExpected(route Expected) bool {
	return validProcessIdentity(route.ProcessIdentity) && validTransport(route.Transport) && canonicalHost(route.Host) != "" && route.Port > 0 && route.RouteID != "" && route.SurfaceID != ""
}

func validTransport(transport Transport) bool {
	return transport == TransportTCP || transport == TransportUDP
}

func canonicalHost(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	return value
}
