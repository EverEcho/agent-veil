package core

import (
	"net/http"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

func (s *Server) listSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.manager.List())
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if err := decodeManagement(r, &request); err != nil || request.TTLSeconds <= 0 || request.TTLSeconds > int64(session.DefaultMaxTTL/time.Second) || len(request.RouteIDs) > session.DefaultMaxRoutes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_REQUEST"})
		return
	}
	for _, routeID := range request.RouteIDs {
		if !s.routeExists(routeID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "UNKNOWN_ROUTE"})
			return
		}
	}
	created, err := s.manager.CreateWithOptions(request.ParentSessionID, s.Endpoint(), request.RouteIDs, time.Duration(request.TTLSeconds)*time.Second, session.CreateOptions{Interactive: request.Interactive})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_SESSION"})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) createChildSession(w http.ResponseWriter, r *http.Request) {
	if !validVersionedLocalRequest(w, r) {
		return
	}
	parentID, routeID := r.PathValue("parent"), r.PathValue("route")
	sessionValues, tokenValues := r.Header.Values(veilproxy.HeaderSession), r.Header.Values(veilproxy.HeaderRouteToken)
	if len(sessionValues) != 1 || len(tokenValues) != 1 || sessionValues[0] != parentID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": string(domain.ErrUnauthorizedRoute)})
		return
	}
	_, ok := s.manager.AuthorizeRoute(parentID, routeID, tokenValues[0])
	protectedRoute, routeAgentKind, routeActive := s.activeRoute(routeID)
	if !ok || !routeActive {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": string(domain.ErrUnauthorizedRoute)})
		return
	}
	var request struct {
		TTLSeconds    int64 `json:"ttl_seconds"`
		MaxTTLSeconds int64 `json:"max_ttl_seconds"`
	}
	if err := decodeManagement(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_CHILD_SESSION"})
		return
	}
	exactTTL, boundedTTL := request.TTLSeconds > 0, request.MaxTTLSeconds > 0
	if exactTTL == boundedTTL || request.TTLSeconds < 0 || request.MaxTTLSeconds < 0 || request.TTLSeconds > int64(session.DefaultMaxTTL/time.Second) || request.MaxTTLSeconds > int64(session.DefaultMaxTTL/time.Second) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_CHILD_SESSION"})
		return
	}
	var created session.Created
	var err error
	if boundedTTL {
		created, err = s.manager.CreateChildWithin(parentID, s.Endpoint(), []string{routeID}, time.Duration(request.MaxTTLSeconds)*time.Second)
	} else {
		created, err = s.manager.CreateWithOptions(parentID, s.Endpoint(), []string{routeID}, time.Duration(request.TTLSeconds)*time.Second, session.CreateOptions{Interactive: false})
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_CHILD_SESSION"})
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		session.Created
		Protocol             domain.Protocol `json:"protocol"`
		CapabilityTransports []string        `json:"capability_transports"`
	}{Created: created, Protocol: protectedRoute.Protocol, CapabilityTransports: routeCapabilityTransports(protectedRoute, routeAgentKind)})
}

func (s *Server) deleteChildSession(w http.ResponseWriter, r *http.Request) {
	if !validVersionedLocalRequest(w, r) {
		return
	}
	sessionID, routeID := r.PathValue("session"), r.PathValue("route")
	sessionValues, tokenValues := r.Header.Values(veilproxy.HeaderSession), r.Header.Values(veilproxy.HeaderRouteToken)
	if len(sessionValues) != 1 || len(tokenValues) != 1 || sessionValues[0] != sessionID || !s.manager.DeleteChildAuthorized(sessionID, routeID, tokenValues[0]) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": string(domain.ErrUnauthorizedRoute)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) routeExists(routeID string) bool {
	_, _, ok := s.activeRoute(routeID)
	return ok
}

func (s *Server) activeRoute(routeID string) (domain.ProtectedRoute, string, bool) {
	if s.registry == nil {
		return domain.ProtectedRoute{}, "", false
	}
	for _, entry := range s.registryEntries() {
		if entry.State != registry.StateActive {
			continue
		}
		for _, route := range entry.Plan.Routes {
			if route.ID == routeID {
				return route, entry.Manifest.Agent.Kind, true
			}
		}
	}
	return domain.ProtectedRoute{}, "", false
}

func routeCapabilityTransports(route domain.ProtectedRoute, agentKind string) []string {
	if agentKind == "hermes" || agentKind == "codex-desktop" {
		return []string{capabilityTransportHeaders, capabilityTransportPath}
	}
	if agentKind == "claude" && route.Auth.Type == domain.AuthAnthropicKey {
		return []string{capabilityTransportAnthropicAPIKey}
	}
	return []string{capabilityTransportHeaders}
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if !s.manager.Delete(r.PathValue("id")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "NOT_FOUND"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
