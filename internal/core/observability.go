package core

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/diagnostic"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
	"github.com/agentveil/agentveil/internal/feedback"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/webui"
)

func (s *Server) listApprovals(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.broker.Pending())
}
func (s *Server) listAudit(w http.ResponseWriter, _ *http.Request) {
	if s.auditReader == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "AUDIT_UNAVAILABLE"})
		return
	}
	events, err := s.auditReader.Recent(time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "AUDIT_READ_FAILED"})
		return
	}
	const limit = 500
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) diagnostics(w http.ResponseWriter, _ *http.Request) {
	status := "ok"
	if s.auditMonitor != nil && s.auditMonitor.failures.Load() > 0 {
		status = "degraded"
	}
	if _, degraded := s.semanticRuntimeStatus(); degraded {
		status = "degraded"
	}
	agents := make([]diagnostic.Agent, 0)
	if s.registry != nil {
		entries := s.registryEntries()
		agents = make([]diagnostic.Agent, 0, len(entries))
		for _, entry := range entries {
			agents = append(agents, diagnostic.Agent{Reference: entry.Manifest.Agent.ID, Kind: entry.Manifest.Agent.Kind, Version: entry.Manifest.Agent.Version, State: string(entry.State), Generation: entry.Generation, Coverage: entry.Plan.Summary, ErrorCode: entry.ErrorCode})
		}
	}
	var events []domain.AuditEvent
	if s.auditReader != nil {
		var err error
		events, err = s.auditReader.Recent(time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "DIAGNOSTIC_AUDIT_READ_FAILED"})
			return
		}
		if len(events) > 500 {
			events = events[len(events)-500:]
		}
	}
	scanner := s.currentScanner()
	report, err := diagnostic.Build(scanner, time.Now().UTC(), status, len(s.manager.List()), agents, events)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "DIAGNOSTIC_SANITIZE_FAILED"})
		return
	}
	payload, err := diagnostic.Marshal(scanner, report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "DIAGNOSTIC_SECONDARY_SCAN_FAILED"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="agentveil-diagnostics.json"`)
	secureCoreResponseHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) reportUnexpectedEgress(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil || s.auditor == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "EGRESS_AUDIT_UNAVAILABLE"})
		return
	}
	var report unexpectedEgressReport
	if err := decodeManagement(r, &report); err != nil || report.SessionID == "" || report.AgentID == "" || report.Generation == 0 || report.RouteID == "" || report.Transport != egress.TransportTCP && report.Transport != egress.TransportUDP {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": string(domain.ErrInvalidContract)})
		return
	}
	entry, ok := s.registryEntry(report.AgentID)
	if !ok || entry.State != registry.StateActive || entry.Generation != report.Generation || !s.manager.ContainsRoute(report.SessionID, report.RouteID) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": string(domain.ErrUnauthorizedRoute)})
		return
	}
	var route *domain.ProtectedRoute
	for index := range entry.Plan.Routes {
		if entry.Plan.Routes[index].ID == report.RouteID {
			route = &entry.Plan.Routes[index]
			break
		}
	}
	if route == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": string(domain.ErrUnauthorizedRoute)})
		return
	}
	event := domain.AuditEvent{
		Timestamp:    time.Now().UTC(),
		SessionID:    report.SessionID,
		AgentID:      report.AgentID,
		SurfaceID:    route.SurfaceID,
		Protocol:     route.Protocol,
		FindingTypes: []string{"network.unexpected_egress." + string(report.Transport)},
		FindingCount: 1,
		Severity:     domain.SeverityCritical,
		Action:       domain.ActionBlock,
		ErrorCode:    domain.ErrUnexpectedEgress,
	}
	if err := s.auditor.Append(event); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "AUDIT_WRITE_FAILED"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getCompatibility(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, compatibility.Current())
}

func (s *Server) getDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.discoverer == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DISCOVERY_UNAVAILABLE"})
		return
	}
	writeJSON(w, http.StatusOK, s.discoverer.DetectAll(r.Context()))
}

func (s *Server) getInspection(w http.ResponseWriter, r *http.Request) {
	inspector, ok := s.discoverer.(interface {
		Inspect(context.Context, string) (domain.AgentManifest, error)
	})
	if !ok || s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "INSPECTION_UNAVAILABLE"})
		return
	}
	manifest, err := inspector.Inspect(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "INSPECTION_FAILED"})
		return
	}
	plan, err := s.registry.Preview(manifest)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "PLAN_FAILED"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Manifest domain.AgentManifest  `json:"manifest"`
		Plan     domain.ProtectionPlan `json:"protection_plan"`
	}{Manifest: manifest, Plan: plan})
}

func (s *Server) testDetection(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Text  string             `json:"text"`
		Scope detectionTestScope `json:"scope,omitempty"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Text == "" || len(request.Text) > 32<<10 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_DETECTION_TEST"})
		return
	}
	baseScope := policy.Scope{AgentID: request.Scope.AgentID, Workspace: request.Scope.Workspace, Provider: request.Scope.Provider, SurfaceID: request.Scope.SurfaceID}
	if err := baseScope.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_DETECTION_SCOPE"})
		return
	}
	matches, err := detector.ScanContent(s.currentScanner(), "/test-input", request.Text)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "DETECTOR_FAILURE"})
		return
	}
	results := make([]detectionTestResult, len(matches))
	engine := s.policyEngine()
	for index := range matches {
		findingScope := baseScope
		findingScope.FindingType = matches[index].Finding.Category
		decision, err := engine.Decide(findingScope, true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "POLICY_EVALUATION_FAILURE"})
			return
		}
		preview := detectionTestDecision{Action: decision.Action, Source: "default", Reason: decision.Reason}
		if decision.Rule != nil {
			matchedScope := decision.Rule.Scope
			preview.Source = "rule"
			preview.MatchedScope = &matchedScope
		}
		results[index] = detectionTestResult{Finding: matches[index].Finding, Decision: preview, PolicyContext: findingScope}
	}
	writeJSON(w, http.StatusOK, detectionTestResponse{Results: results})
}

func (s *Server) reportFalsePositive(w http.ResponseWriter, r *http.Request) {
	if s.feedbackStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "FEEDBACK_STORE_UNAVAILABLE"})
		return
	}
	var request struct {
		Finding       domain.Finding `json:"finding"`
		PolicyAction  domain.Action  `json:"policy_action"`
		PolicyContext policy.Scope   `json:"policy_context"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Finding.Location.Path != "/test-input" || request.Finding.Validate(request.Finding.Location.End) != nil || !request.PolicyAction.Valid() || request.PolicyContext.Validate() != nil || request.PolicyContext.FindingType != request.Finding.Category {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_FALSE_POSITIVE_FEEDBACK"})
		return
	}
	entry := feedback.Entry{
		Timestamp:       time.Now().UTC(),
		RuleID:          request.Finding.RuleID,
		Category:        request.Finding.Category,
		Detector:        request.Finding.Detector,
		Severity:        request.Finding.Severity,
		Confidence:      request.Finding.Confidence,
		SuggestedAction: request.Finding.SuggestedAction,
		PolicyAction:    request.PolicyAction,
		Scope:           request.PolicyContext,
	}
	if err := s.feedbackStore.Append(entry); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "FEEDBACK_STORE_FAILURE"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getCallTree(w http.ResponseWriter, _ *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	owners := map[string]registry.CallSurface{}
	for _, entry := range s.registryEntries() {
		if entry.State != registry.StateActive {
			continue
		}
		for _, route := range entry.Plan.Routes {
			owners[route.ID] = registry.CallSurface{RouteID: route.ID, AgentID: entry.Manifest.Agent.ID, SurfaceID: route.SurfaceID, Protocol: route.Protocol, PolicyID: route.PolicyID, Coverage: domain.CoverageProtected}
		}
	}
	activeSessions := s.manager.List()
	auditBySession := make(map[string]*registry.CallAudit)
	if s.auditReader != nil {
		events, err := s.auditReader.Recent(time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CALL_TREE_AUDIT_FAILED"})
			return
		}
		for _, event := range events {
			if event.SessionID == "" {
				continue
			}
			summary := auditBySession[event.SessionID]
			if summary == nil {
				summary = &registry.CallAudit{}
				auditBySession[event.SessionID] = summary
			}
			summary.EventCount++
			summary.FindingCount += event.FindingCount
			if summary.LastAt.IsZero() || event.Timestamp.After(summary.LastAt) {
				summary.LastAt = event.Timestamp
				summary.LastAction = event.Action
			}
		}
	}
	nodes := make([]registry.CallNode, 0)
	for _, activeSession := range activeSessions {
		node := registry.CallNode{SessionID: activeSession.ID, ParentSessionID: activeSession.ParentSessionID, Interactive: activeSession.Interactive, ExpiresAt: activeSession.ExpiresAt, Audit: auditBySession[activeSession.ID]}
		for _, routeID := range activeSession.RouteIDs {
			owner, ok := owners[routeID]
			if !ok {
				owner = registry.CallSurface{RouteID: routeID, Coverage: domain.CoverageUnprotected}
			}
			node.Surfaces = append(node.Surfaces, owner)
		}
		nodes = append(nodes, node)
	}
	tree, err := registry.CallTree(nodes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CALL_TREE_INVALID"})
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	secureCoreResponseHeaders(w.Header())
	if !webui.Serve(w, r) {
		http.NotFound(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	result := map[string]string{"status": "ok", "api_version": APIVersion, "audit": "disabled"}
	semantic, semanticDegraded := s.semanticRuntimeStatus()
	result["semantic"] = semantic
	if semanticDegraded {
		result["status"] = "degraded"
	}
	if s.auditMonitor != nil {
		result["audit"] = "ok"
		if failures := s.auditMonitor.failures.Load(); failures > 0 {
			result["status"] = "degraded"
			result["audit"] = "error"
			result["audit_failures"] = strconv.FormatUint(failures, 10)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) semanticRuntimeStatus() (string, bool) {
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	if s.semantic != nil && s.semanticVersion != "" {
		return "active", false
	}
	if s.semanticRequired {
		return "required_unavailable", true
	}
	if s.semanticLoader != nil {
		return "ready", false
	}
	return "disabled", false
}
