package domain

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxManifestSurfaces = 256
	MaxMetadataEntries  = 64
	maxDisplayTextBytes = 256
	maxReferenceBytes   = 4096
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	referencePattern  = regexp.MustCompile(`^(?:environment|keychain|native|agent):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func (m AgentManifest) Validate() error {
	if m.SchemaVersion != "v1" || !identifierPattern.MatchString(m.Agent.ID) || !identifierPattern.MatchString(m.Agent.Kind) {
		return NewError(ErrInvalidContract, "validate manifest", "schema version and agent identity are required")
	}
	if m.Agent.Mode != "" && !m.Agent.Mode.Valid() || len(m.Agent.Version) > 128 || !utf8.ValidString(m.Agent.Version) || len(m.Agent.Executable) > maxReferenceBytes || !utf8.ValidString(m.Agent.Executable) || strings.ContainsRune(m.Agent.Executable, 0) || !validMetadata(m.Agent.Metadata) {
		return NewError(ErrInvalidContract, "validate manifest", "agent mode, version, executable, or metadata is invalid")
	}
	if len(m.Surfaces) == 0 || len(m.Surfaces) > MaxManifestSurfaces {
		return NewError(ErrInvalidContract, "validate manifest", "surface count must be within its configured bounds")
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
	if !identifierPattern.MatchString(s.ID) || s.Name == "" || len(s.Name) > maxDisplayTextBytes || !utf8.ValidString(s.Name) || s.ConfigSource == "" || len(s.ConfigSource) > maxReferenceBytes || !utf8.ValidString(s.ConfigSource) || strings.ContainsRune(s.ConfigSource, 0) || !validMetadata(s.Metadata) {
		return NewError(ErrInvalidContract, "validate surface", "id, name and config source are required")
	}
	if !s.Type.Valid() || !s.Protocol.Valid() {
		return NewError(ErrInvalidContract, "validate surface", "surface type or protocol is invalid")
	}
	if s.Network != nil {
		if err := s.Network.Validate(); err != nil {
			return err
		}
	}
	if s.Protocol == ProtocolUnknown || s.Type == SurfaceUnknown {
		if s.Auth.Type != "" {
			return s.Auth.Validate()
		}
		return nil
	}
	if s.Protocol == ProtocolLocalStdio {
		if s.Network != nil {
			return NewError(ErrInvalidContract, "validate surface", "local stdio cannot bind a network route")
		}
		if s.Upstream != nil {
			return NewError(ErrInvalidContract, "validate surface", "local stdio cannot have a network upstream")
		}
		if s.Type != SurfaceMCPStdio {
			return NewError(ErrInvalidContract, "validate surface", "local stdio protocol requires an MCP stdio surface")
		}
		return nil
	}
	if s.Upstream == nil {
		return NewError(ErrInvalidContract, "validate surface", "network surface requires an upstream")
	}
	if err := s.Upstream.Validate(); err != nil {
		return err
	}
	return s.Auth.Validate()
}

func (u Upstream) Validate() error {
	if u.Scheme != "https" && u.Scheme != "http" {
		return NewError(ErrInvalidContract, "validate upstream", "scheme must be https or http")
	}
	if strings.TrimSpace(u.Host) == "" || len(u.Host) > 253 || !utf8.ValidString(u.Host) || strings.TrimSpace(u.Host) != u.Host || strings.ContainsAny(u.Host, "/@?# \t\r\n") {
		return NewError(ErrInvalidContract, "validate upstream", "host is empty or malformed")
	}
	if u.Port == 0 {
		return NewError(ErrInvalidContract, "validate upstream", "port is required")
	}
	if len(u.Path) > maxReferenceBytes || !utf8.ValidString(u.Path) {
		return NewError(ErrInvalidContract, "validate upstream", "base path exceeds its limit")
	}
	if u.Path != "" {
		if !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") || strings.ContainsAny(u.Path, "\\?#\r\n\t") {
			return NewError(ErrInvalidContract, "validate upstream", "base path is malformed")
		}
		for _, segment := range strings.Split(u.Path, "/") {
			if segment == "." || segment == ".." {
				return NewError(ErrInvalidContract, "validate upstream", "base path contains traversal")
			}
		}
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Host) {
		return NewError(ErrUpstreamDenied, "validate upstream", "plaintext HTTP is allowed only for loopback")
	}
	return nil
}

func (a AuthStrategy) Validate() error {
	if !a.Type.Valid() {
		return NewError(ErrInvalidContract, "validate auth", "authentication type is invalid")
	}
	if a.Type != AuthPassthrough && a.Source == "" {
		return NewError(ErrInvalidContract, "validate auth", "non-passthrough authentication requires a credential source")
	}
	if a.Source != "" && !referencePattern.MatchString(a.Source) {
		return NewError(ErrInvalidContract, "validate auth", "credential source must be an indirect reference")
	}
	return nil
}

func (n NetworkRoute) Validate() error {
	if !n.Type.Valid() {
		return NewError(ErrInvalidContract, "validate network route", "network route type is invalid")
	}
	if n.Type == NetworkDirect || n.Type == NetworkSystemProxy {
		if n.Endpoint != "" {
			return NewError(ErrInvalidContract, "validate network route", "direct and system routes cannot have an explicit endpoint")
		}
		return nil
	}
	if len(n.Endpoint) > maxReferenceBytes || !utf8.ValidString(n.Endpoint) {
		return NewError(ErrInvalidContract, "validate network route", "proxy endpoint exceeds its limit")
	}
	endpoint, err := url.Parse(n.Endpoint)
	if err != nil || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return NewError(ErrInvalidContract, "validate network route", "proxy endpoint must be an origin without embedded credentials")
	}
	if port, err := strconv.ParseUint(endpoint.Port(), 10, 16); err != nil || port == 0 {
		return NewError(ErrInvalidContract, "validate network route", "proxy endpoint port is invalid")
	}
	if n.Type == NetworkHTTPProxy && endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return NewError(ErrInvalidContract, "validate network route", "HTTP proxy endpoint scheme is invalid")
	}
	if n.Type == NetworkSOCKS5 && endpoint.Scheme != "socks5" {
		return NewError(ErrInvalidContract, "validate network route", "SOCKS5 endpoint scheme is invalid")
	}
	return nil
}

func validMetadata(metadata map[string]string) bool {
	if len(metadata) > MaxMetadataEntries {
		return false
	}
	for key, value := range metadata {
		if !identifierPattern.MatchString(key) || len(value) > maxReferenceBytes || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return false
		}
	}
	return true
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
	if !identifierPattern.MatchString(f.RuleID) || !identifierPattern.MatchString(f.Category) || !identifierPattern.MatchString(f.Detector) {
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
