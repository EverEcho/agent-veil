package transparent

import (
	"net"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
)

const (
	maxScopeProcesses = 1024
	maxScopeDomains   = 256
)

type Scope struct {
	SessionID string
	Processes map[egress.ProcessIdentity]struct{}
	Domains   map[string]struct{}
}

func NewScope(sessionID string, processes []egress.ProcessIdentity, domains []string) (Scope, error) {
	if !validSessionID(sessionID) || len(processes) == 0 || len(processes) > maxScopeProcesses || len(domains) == 0 || len(domains) > maxScopeDomains {
		return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "session, processes and domains are required")
	}
	scope := Scope{SessionID: sessionID, Processes: map[egress.ProcessIdentity]struct{}{}, Domains: map[string]struct{}{}}
	seenPIDs := make(map[int]struct{}, len(processes))
	for _, process := range processes {
		if process.ProcessID <= 0 || process.StartedAt == 0 {
			return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "process id is invalid")
		}
		if _, duplicate := seenPIDs[process.ProcessID]; duplicate {
			return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "process scope contains a reused PID")
		}
		seenPIDs[process.ProcessID] = struct{}{}
		scope.Processes[process] = struct{}{}
	}
	for _, value := range domains {
		host := canonicalHost(value)
		if !validDNSName(host) || net.ParseIP(host) != nil {
			return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "domain is invalid")
		}
		scope.Domains[host] = struct{}{}
	}
	return scope, nil
}

func validSessionID(value string) bool {
	if value == "" || len(value) > 128 {
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

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/@?#*:%") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (s Scope) Allows(sessionID string, process egress.ProcessIdentity, hostname string) bool {
	if sessionID != s.SessionID {
		return false
	}
	if _, ok := s.Processes[process]; !ok {
		return false
	}
	_, ok := s.Domains[canonicalHost(hostname)]
	return ok
}
func canonicalHost(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
