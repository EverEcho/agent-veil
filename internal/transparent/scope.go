package transparent

import (
	"net"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type Scope struct {
	SessionID  string
	ProcessIDs map[int]struct{}
	Domains    map[string]struct{}
}

func NewScope(sessionID string, processIDs []int, domains []string) (Scope, error) {
	if sessionID == "" || len(processIDs) == 0 || len(domains) == 0 {
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
		if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, "/@?#*") {
			return Scope{}, domain.NewError(domain.ErrInvalidContract, "create transparent scope", "domain is invalid")
		}
		scope.Domains[host] = struct{}{}
	}
	return scope, nil
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
