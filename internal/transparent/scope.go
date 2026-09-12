package transparent

import (
	"net"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const (
	maxScopeProcesses = 1024
	maxScopeDomains   = 256
)

type Scope struct {
	SessionID  string
	ProcessIDs map[int]struct{}
	Domains    map[string]struct{}
}

func NewScope(sessionID string, processIDs []int, domains []string) (Scope, error) {
	if !validSessionID(sessionID) || len(processIDs) == 0 || len(processIDs) > maxScopeProcesses || len(domains) == 0 || len(domains) > maxScopeDomains {
		return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "session, processes and domains are required")
	}
	scope := Scope{SessionID: sessionID, ProcessIDs: map[int]struct{}{}, Domains: map[string]struct{}{}}
	for _, pid := range processIDs {
		if pid <= 0 {
			return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "process id is invalid")
		}
		scope.ProcessIDs[pid] = struct{}{}
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

func (s Scope) Allows(sessionID string, processID int, hostname string) bool {
	if sessionID != s.SessionID {
		return false
	}
	if _, ok := s.ProcessIDs[processID]; !ok {
		return false
	}
	_, ok := s.Domains[canonicalHost(hostname)]
	return ok
}
func canonicalHost(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
