package domain

import (
	"fmt"
	"net"
	"strings"
)

func (m AgentManifest) Validate() error {
	if m.SchemaVersion == "" || m.Agent.ID == "" || m.Agent.Kind == "" {
		return NewError(ErrInvalidContract, "validate manifest", "schema version and agent identity are required")
	}
	seen := make(map[string]struct{}, len(m.Surfaces))
	for i, surface := range m.Surfaces {
		if err := surface.Validate(); err != nil {
			return NewError(ErrInvalidContract, "validate manifest", fmt.Sprintf("surface %d: %v", i, err))
		}
		if _, ok := seen[surface.ID]; ok {
			return NewError(ErrInvalidContract, "validate manifest", "duplicate surface id")
		}
		seen[surface.ID] = struct{}{}
	}
	return nil
}

func (s EgressSurface) Validate() error {
	if s.ID == "" || s.Name == "" || s.ConfigSource == "" {
		return NewError(ErrInvalidContract, "validate surface", "id, name and config source are required")
	}
	if !s.Type.Valid() || !s.Protocol.Valid() {
		return NewError(ErrInvalidContract, "validate surface", "surface type or protocol is invalid")
	}
	if s.Protocol == ProtocolUnknown || s.Type == SurfaceUnknown {
		return nil
	}
	if s.Protocol == ProtocolLocalStdio {
		if s.Upstream != nil {
			return NewError(ErrInvalidContract, "validate surface", "local stdio cannot have a network upstream")
		}
		return nil
	}
	if s.Upstream == nil {
		return NewError(ErrInvalidContract, "validate surface", "network surface requires an upstream")
	}
	return s.Upstream.Validate()
}

func (u Upstream) Validate() error {
	if u.Scheme != "https" && u.Scheme != "http" {
		return NewError(ErrInvalidContract, "validate upstream", "scheme must be https or http")
	}
	if strings.TrimSpace(u.Host) == "" || strings.ContainsAny(u.Host, "/@?#") {
		return NewError(ErrInvalidContract, "validate upstream", "host is empty or malformed")
	}
	if u.Port == 0 {
		return NewError(ErrInvalidContract, "validate upstream", "port is required")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Host) {
		return NewError(ErrUpstreamDenied, "validate upstream", "plaintext HTTP is allowed only for loopback")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (f Finding) Validate(contentLength int) error {
	if f.RuleID == "" || f.Category == "" || f.Detector == "" {
		return NewError(ErrInvalidContract, "validate finding", "rule, category and detector are required")
	}
	if !f.Severity.Valid() || !f.SuggestedAction.Valid() || f.Confidence < 0 || f.Confidence > 1 {
		return NewError(ErrInvalidContract, "validate finding", "severity, action or confidence is invalid")
	}
	if f.Location.Start < 0 || f.Location.End <= f.Location.Start || f.Location.End > contentLength {
		return NewError(ErrInvalidContract, "validate finding", "content range is invalid")
	}
	return nil
}
