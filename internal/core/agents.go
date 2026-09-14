package core

import (
	"net/http"
	"strconv"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/registry"
)

func (s *Server) listAgents(w http.ResponseWriter, _ *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	writeJSON(w, http.StatusOK, s.registryEntries())
}

func (s *Server) registryEntries() []registry.Entry {
	entries := s.registry.List()
	s.applyRegistryRevocations()
	return entries
}

func (s *Server) registryEntry(agentID string) (registry.Entry, bool) {
	entry, ok := s.registry.Get(agentID)
	s.applyRegistryRevocations()
	return entry, ok
}

func (s *Server) applyRegistryRevocations() {
	routeIDs, all := s.registry.DrainRouteRevocations()
	if all {
		s.manager.DeleteAll()
		return
	}
	s.manager.DeleteRoutes(routeIDs)
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	entry, ok := s.registryEntry(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "NOT_FOUND"})
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) registerAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	defer s.applyRegistryRevocations()
	var manifest domain.AgentManifest
	if err := decodeManagement(r, &manifest); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_MANIFEST"})
		return
	}
	entry, err := s.registry.Reconcile(manifest)
	if err != nil {
		writeJSON(w, http.StatusConflict, entry)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) registerLeasedAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	defer s.applyRegistryRevocations()
	var request struct {
		Manifest   domain.AgentManifest `json:"manifest"`
		TTLSeconds int64                `json:"ttl_seconds"`
	}
	if err := decodeManagement(r, &request); err != nil || request.TTLSeconds < 1 || request.TTLSeconds > maxIntegrationLeaseSeconds {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_INTEGRATION_LEASE"})
		return
	}
	entry, err := s.registry.ReconcileLeased(request.Manifest, time.Duration(request.TTLSeconds)*time.Second)
	if err != nil {
		writeJSON(w, http.StatusConflict, entry)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) heartbeatAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	defer s.applyRegistryRevocations()
	var request struct {
		Generation uint64 `json:"generation"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Generation == 0 || request.TTLSeconds < 1 || request.TTLSeconds > maxIntegrationLeaseSeconds {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_INTEGRATION_HEARTBEAT"})
		return
	}
	entry, err := s.registry.Heartbeat(r.PathValue("id"), request.Generation, time.Duration(request.TTLSeconds)*time.Second)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": string(domain.ErrUnauthorizedRoute)})
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	defer s.applyRegistryRevocations()
	generationValue := r.URL.Query().Get("generation")
	entry, exists := s.registryEntry(r.PathValue("id"))
	if generationValue != "" {
		generation, err := strconv.ParseUint(generationValue, 10, 64)
		if err != nil || generation == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_INTEGRATION_GENERATION"})
			return
		}
		if !exists || entry.Generation != generation || !s.registry.RemoveGeneration(r.PathValue("id"), generation) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "STALE_INTEGRATION_GENERATION"})
			return
		}
	} else {
		s.registry.Remove(r.PathValue("id"))
	}
	w.WriteHeader(http.StatusNoContent)
}
