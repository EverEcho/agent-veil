package core

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/domain"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/registry"
)

func (s *Server) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeID, ok := routeIDFromPath(r.URL.Path)
		if !ok || s.registry == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "UNKNOWN_ROUTE"})
			return
		}
		var selected *domain.ProtectedRoute
		var selectedAgentID string
		var selectedAgentKind string
		var selectedWorkspace string
		for _, entry := range s.registryEntries() {
			if entry.State != registry.StateActive {
				continue
			}
			for i := range entry.Plan.Routes {
				route := entry.Plan.Routes[i]
				if route.ID == routeID {
					selected = &route
					selectedAgentID = entry.Manifest.Agent.ID
					selectedAgentKind = entry.Manifest.Agent.Kind
					selectedWorkspace = entry.Manifest.Agent.Metadata["workspace"]
					break
				}
			}
		}
		if selected == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "UNKNOWN_ROUTE"})
			return
		}
		slots := s.proxySlots
		if r.Method == http.MethodGet && (selected.Protocol == domain.ProtocolMCPStreamable || selected.Protocol == domain.ProtocolMCPLegacySSE) {
			slots = s.streamSlots
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "CONCURRENCY_LIMIT"})
			return
		}
		upstream := &url.URL{Scheme: selected.Upstream.Scheme, Host: net.JoinHostPort(selected.Upstream.Host, strconv.Itoa(int(selected.Upstream.Port))), Path: selected.Upstream.Path}
		if err := selected.Upstream.Validate(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "INVALID_ROUTE"})
			return
		}
		authApplier, err := veilauth.NewRuntimeApplier(selected.Auth, upstream)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "INVALID_ROUTE"})
			return
		}
		workspaceRef := ""
		if selectedWorkspace != "" {
			workspaceRef = audit.WorkspaceReference(selectedWorkspace)
		}
		capabilityHeader := ""
		capabilityTransports := routeCapabilityTransports(*selected, selectedAgentKind)
		if slices.Contains(capabilityTransports, capabilityTransportAnthropicAPIKey) {
			capabilityHeader = "X-Api-Key"
		}
		handler, err := veilproxy.NewHandlerWithScanner(s.manager, []veilproxy.Route{{ID: selected.ID, AgentID: selectedAgentID, SurfaceID: selected.SurfaceID, Workspace: workspaceRef, WorkspaceRef: workspaceRef, Protocol: selected.Protocol, Upstream: upstream, Auth: selected.Auth, AuthApplier: authApplier, Network: selected.Network, Auditor: s.auditor, CapabilityHeader: capabilityHeader, CapabilityPath: slices.Contains(capabilityTransports, capabilityTransportPath), LegacySessions: s.legacySSE, Policy: s.policyEngine(), Interactive: true, Approver: s.broker, MaxRequestBytes: 8 << 20, MaxResponseBytes: 32 << 20, VaultLimits: redactor.Limits{MaxEntries: 4096, MaxOriginalBytes: 8 << 20}}}, &http.Client{Timeout: 5 * time.Minute}, s.currentScanner())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "INVALID_ROUTE"})
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func routeIDFromPath(path string) (string, bool) {
	rest := strings.TrimPrefix(path, "/route/")
	if rest == path {
		return "", false
	}
	id, _, found := strings.Cut(rest, "/")
	return id, found && id != ""
}
