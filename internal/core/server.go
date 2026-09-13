package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/diagnostic"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
	"github.com/agentveil/agentveil/internal/feedback"
	"github.com/agentveil/agentveil/internal/jsonsafe"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/protocol"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/security"
	"github.com/agentveil/agentveil/internal/session"
)

const maxManagementBody = 64 << 10
const maxRuleInstallBody = 2 << 20
const maxModelManifestHeaderBytes = 8 << 10
const maxModelUploadDuration = 15 * time.Minute
const defaultMaxConcurrentProxyRequests = 64
const maxConcurrentProxyRequests = 4096
const maxIntegrationLeaseSeconds = 3600
const defaultSessionCleanupInterval = 100 * time.Millisecond
const minAdminTokenBytes = 32
const maxAdminTokenBytes = 4096

const APIVersion = "v1"
const APIVersionHeader = "X-AgentVeil-API-Version"

const (
	capabilityTransportHeaders         = "headers"
	capabilityTransportAnthropicAPIKey = "anthropic_api_key"
	capabilityTransportPath            = "path"
)

type SemanticRuntimeLoader interface {
	Load(*os.File, modelstore.Manifest) (detector.Semantic, error)
}

type Server struct {
	lifecycleMu      sync.Mutex
	manager          *session.Manager
	adminToken       string
	listener         net.Listener
	httpServer       *http.Server
	registry         *registry.Registry
	broker           *policy.Broker
	policy           policy.Engine
	policyMu         sync.RWMutex
	policyStore      *policy.Store
	ruleStore        *rulestore.Store
	modelStore       *modelstore.Store
	scannerMu        sync.RWMutex
	semanticLoader   SemanticRuntimeLoader
	semantic         detector.Semantic
	semanticRequired bool
	semanticVersion  string
	auditor          interface {
		Append(domain.AuditEvent) error
	}
	auditMonitor *monitoredAuditor
	auditReader  interface {
		Recent(time.Time) ([]domain.AuditEvent, error)
	}
	feedbackStore *feedback.Store
	proxySlots    chan struct{}
	discoverer    interface {
		DetectAll(context.Context) []discovery.Detection
	}
	scanner       detector.ContentScanner
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
}

type monitoredAuditor struct {
	target   interface{ Append(domain.AuditEvent) error }
	failures atomic.Uint64
}

func (m *monitoredAuditor) Append(event domain.AuditEvent) error {
	err := m.target.Append(event)
	if err != nil {
		m.failures.Add(1)
	}
	return err
}

func (s *Server) WithRegistry(value *registry.Registry) *Server { s.registry = value; return s }

func New(manager *session.Manager, adminToken string) (*Server, error) {
	if manager == nil || !validAdminToken(adminToken) {
		return nil, errors.New("manager and a bounded visible-ASCII admin token of at least 32 characters are required")
	}
	scanner, err := detector.NewDefaultChunked()
	if err != nil {
		return nil, err
	}
	return &Server{manager: manager, adminToken: adminToken, broker: policy.NewBroker(), policy: policy.Engine{Default: domain.ActionRedact}, proxySlots: make(chan struct{}, defaultMaxConcurrentProxyRequests), discoverer: discovery.Default(), scanner: scanner}, nil
}

func (s *Server) WithDiscoverer(value interface {
	DetectAll(context.Context) []discovery.Detection
}) *Server {
	s.discoverer = value
	return s
}

func (s *Server) WithProxyConcurrency(limit int) error {
	if limit <= 0 || limit > maxConcurrentProxyRequests {
		return domain.NewError(domain.ErrInvalidContract, "configure proxy concurrency", "limit must be within its configured bounds")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener != nil {
		return domain.NewError(domain.ErrInvalidContract, "configure proxy concurrency", "limit cannot change after the server starts")
	}
	s.proxySlots = make(chan struct{}, limit)
	return nil
}

func (s *Server) WithPolicy(engine policy.Engine) *Server {
	s.policyMu.Lock()
	s.policy = engine
	s.policyMu.Unlock()
	return s
}

func (s *Server) WithPolicyStore(store *policy.Store) error {
	if store == nil {
		return domain.NewError(domain.ErrInvalidContract, "configure policy", "policy store is required")
	}
	document, err := store.Load()
	if errors.Is(err, os.ErrNotExist) {
		document = policy.DefaultDocument()
		if err := store.Save(document); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	engine, err := document.Engine()
	if err != nil {
		return err
	}
	s.policyMu.Lock()
	s.policyStore = store
	s.policy = engine
	s.policyMu.Unlock()
	return nil
}

func (s *Server) WithRuleStore(store *rulestore.Store) error {
	if store == nil {
		return domain.NewError(domain.ErrInvalidContract, "configure rules", "rule store is required")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener != nil {
		return domain.NewError(domain.ErrInvalidContract, "configure rules", "rule store cannot change after the server starts")
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	previous := s.ruleStore
	s.ruleStore = store
	scanner, err := s.buildScannerLocked(s.semantic, s.semanticRequired)
	if err != nil {
		s.ruleStore = previous
		return err
	}
	s.scanner = scanner
	return nil
}
func (s *Server) WithModelStore(store *modelstore.Store) error {
	if store == nil {
		return domain.NewError(domain.ErrInvalidContract, "configure models", "model store is required")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener != nil {
		return domain.NewError(domain.ErrInvalidContract, "configure models", "model store cannot change after the server starts")
	}
	file, _, err := store.OpenActive()
	if err == nil {
		err = file.Close()
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.modelStore = store
	return nil
}

func (s *Server) WithSemanticRuntime(loader SemanticRuntimeLoader, required bool) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener != nil {
		return domain.NewError(domain.ErrInvalidContract, "configure semantic runtime", "semantic runtime cannot change after the server starts")
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	var semantic detector.Semantic
	version := ""
	if s.modelStore != nil {
		file, manifest, err := s.modelStore.OpenActive()
		if err == nil {
			if loader == nil {
				if err = file.Close(); err != nil {
					return err
				}
			} else {
				semantic, err = loader.Load(file, manifest)
				closeErr := file.Close()
				if err == nil {
					err = closeErr
				}
				if err != nil || semantic == nil {
					return domain.NewError(domain.ErrDetectorFailure, "configure semantic runtime", "active semantic model could not be loaded")
				}
				version = manifest.Version
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	scanner, err := s.buildScannerLocked(semantic, required)
	if err != nil {
		return err
	}
	s.semanticLoader = loader
	s.semantic = semantic
	s.semanticRequired = required
	s.semanticVersion = version
	s.scanner = scanner
	return nil
}
func (s *Server) WithAuditor(value interface{ Append(domain.AuditEvent) error }) *Server {
	if value == nil {
		s.auditor = nil
		s.auditMonitor = nil
		s.auditReader = nil
		return s
	}
	monitor := &monitoredAuditor{target: value}
	s.auditor = monitor
	s.auditMonitor = monitor
	if reader, ok := value.(interface {
		Recent(time.Time) ([]domain.AuditEvent, error)
	}); ok {
		s.auditReader = reader
	}
	return s
}

func (s *Server) WithFeedbackStore(store *feedback.Store) error {
	if store == nil {
		return domain.NewError(domain.ErrInvalidContract, "configure feedback", "feedback store is required")
	}
	s.feedbackStore = store
	return nil
}

func (s *Server) Start() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener != nil || s.httpServer != nil {
		return domain.NewError(domain.ErrInvalidContract, "start Core", "server is already started")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.listener = listener
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.auth(s.health))
	mux.HandleFunc("GET /v1/sessions", s.auth(s.listSessions))
	mux.HandleFunc("POST /v1/sessions", s.auth(s.createSession))
	mux.HandleFunc("POST /v1/sessions/{parent}/routes/{route}/children", s.createChildSession)
	mux.HandleFunc("DELETE /v1/sessions/{session}/routes/{route}", s.deleteChildSession)
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.auth(s.deleteSession))
	mux.HandleFunc("GET /v1/agents", s.auth(s.listAgents))
	mux.HandleFunc("GET /v1/agents/{id}", s.auth(s.getAgent))
	mux.HandleFunc("POST /v1/agents", s.auth(s.registerAgent))
	mux.HandleFunc("POST /v1/agents/leases", s.auth(s.registerLeasedAgent))
	mux.HandleFunc("POST /v1/agents/{id}/heartbeat", s.auth(s.heartbeatAgent))
	mux.HandleFunc("DELETE /v1/agents/{id}", s.auth(s.deleteAgent))
	mux.HandleFunc("GET /v1/approvals", s.auth(s.listApprovals))
	mux.HandleFunc("POST /v1/approvals/{id}", s.auth(s.resolveApproval))
	mux.HandleFunc("GET /v1/audit", s.auth(s.listAudit))
	mux.HandleFunc("GET /v1/diagnostics", s.auth(s.diagnostics))
	mux.HandleFunc("POST /v1/egress-events", s.auth(s.reportUnexpectedEgress))
	mux.HandleFunc("GET /v1/call-tree", s.auth(s.getCallTree))
	mux.HandleFunc("GET /v1/policy", s.auth(s.getPolicy))
	mux.HandleFunc("PUT /v1/policy", s.auth(s.updatePolicy))
	mux.HandleFunc("GET /v1/compatibility", s.auth(s.getCompatibility))
	mux.HandleFunc("GET /v1/discovery", s.auth(s.getDiscovery))
	mux.HandleFunc("GET /v1/discovery/{id}", s.auth(s.getInspection))
	mux.HandleFunc("POST /v1/detect", s.auth(s.testDetection))
	mux.HandleFunc("POST /v1/feedback/false-positives", s.auth(s.reportFalsePositive))
	mux.HandleFunc("GET /v1/rules", s.auth(s.listRulePacks))
	mux.HandleFunc("POST /v1/rules", s.auth(s.installRulePack))
	mux.HandleFunc("PUT /v1/rules/active", s.auth(s.activateRulePack))
	mux.HandleFunc("DELETE /v1/rules/active", s.auth(s.deactivateRulePack))
	mux.HandleFunc("DELETE /v1/rules/{version}", s.auth(s.removeRulePack))
	mux.HandleFunc("GET /v1/models", s.auth(s.listModels))
	mux.HandleFunc("POST /v1/models", s.auth(s.installModel))
	mux.HandleFunc("PUT /v1/models/active", s.auth(s.activateModel))
	mux.HandleFunc("DELETE /v1/models/active", s.auth(s.deactivateModel))
	mux.HandleFunc("DELETE /v1/models/{version}", s.auth(s.removeModel))
	mux.HandleFunc("GET /", s.dashboard)
	mux.Handle("POST /route/", s.proxyHandler())
	mux.Handle("GET /route/", s.proxyHandler())
	mux.Handle("DELETE /route/", s.proxyHandler())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secureCoreResponseHeaders(w.Header())
		if !security.ValidLoopbackAuthority(r.Host) {
			writeJSON(w, http.StatusMisdirectedRequest, map[string]string{"error": string(domain.ErrInvalidAuthority)})
			return
		}
		mux.ServeHTTP(w, r)
	})
	s.httpServer = &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	cleanupContext, cancelCleanup := context.WithCancel(context.Background())
	s.cleanupCancel = cancelCleanup
	s.cleanupDone = make(chan struct{})
	go func() {
		defer close(s.cleanupDone)
		ticker := time.NewTicker(defaultSessionCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.manager.PruneExpired()
			case <-cleanupContext.Done():
				return
			}
		}
	}()
	go func() { _ = s.httpServer.Serve(listener) }()
	return nil
}

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
		entries := s.registry.List()
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

type unexpectedEgressReport struct {
	SessionID  string           `json:"session_id"`
	AgentID    string           `json:"agent_id"`
	Generation uint64           `json:"generation"`
	RouteID    string           `json:"route_id"`
	Transport  egress.Transport `json:"transport"`
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
	entry, ok := s.registry.Get(report.AgentID)
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
func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	engine := s.policyEngine()
	writeJSON(w, http.StatusOK, policy.Document{SchemaVersion: "v1", Default: engine.Default, Rules: engine.Rules})
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

type detectionTestScope struct {
	AgentID   string `json:"agent_id,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	Provider  string `json:"provider,omitempty"`
	SurfaceID string `json:"surface_id,omitempty"`
}

type detectionTestDecision struct {
	Action       domain.Action `json:"action"`
	Source       string        `json:"source"`
	Reason       string        `json:"reason"`
	MatchedScope *policy.Scope `json:"matched_scope,omitempty"`
}

type detectionTestResult struct {
	Finding       domain.Finding        `json:"finding"`
	Decision      detectionTestDecision `json:"decision"`
	PolicyContext policy.Scope          `json:"policy_context"`
}

type detectionTestResponse struct {
	Results []detectionTestResult `json:"results"`
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

type rulePackInventory struct {
	Active   string               `json:"active,omitempty"`
	Versions []rulestore.Manifest `json:"versions"`
}

type rulePackInstall struct {
	Manifest       rulestore.Manifest `json:"manifest"`
	ArtifactBase64 string             `json:"artifact_base64"`
}

func (s *Server) listRulePacks(w http.ResponseWriter, _ *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	versions, err := s.ruleStore.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RULE_INVENTORY_FAILED"})
		return
	}
	inventory := rulePackInventory{Versions: versions}
	_, active, err := s.ruleStore.OpenActive()
	if err == nil {
		inventory.Active = active.Version
	} else if !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_RULE_INVALID"})
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (s *Server) installRulePack(w http.ResponseWriter, r *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	var request rulePackInstall
	if err := decodeManagementWithLimit(r, &request, maxRuleInstallBody); err != nil || request.ArtifactBase64 == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_RULE_PACK"})
		return
	}
	payload, err := base64.StdEncoding.DecodeString(request.ArtifactBase64)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != request.ArtifactBase64 || int64(len(payload)) != request.Manifest.Size {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_RULE_PACK"})
		return
	}
	if err := s.ruleStore.Install(request.Manifest, bytes.NewReader(payload)); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_INSTALLATION_FAILED"})
		return
	}
	writeJSON(w, http.StatusCreated, request.Manifest)
}

func (s *Server) activateRulePack(w http.ResponseWriter, r *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	var request struct {
		Version string `json:"version"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_RULE_VERSION"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	pack, _, err := s.ruleStore.Open(request.Version)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_ACTIVATION_FAILED"})
		return
	}
	base, err := detector.NewDefaultWithRulePack(pack)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_ACTIVATION_FAILED"})
		return
	}
	base.WithSemantic(s.semantic, s.semanticRequired)
	scanner, err := detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
	if err != nil || s.ruleStore.Activate(request.Version) != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_ACTIVATION_FAILED"})
		return
	}
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deactivateRulePack(w http.ResponseWriter, _ *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	base := detector.NewDefault().WithSemantic(s.semantic, s.semanticRequired)
	scanner, err := detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RULE_DEACTIVATION_FAILED"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	if err := s.ruleStore.Deactivate(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RULE_DEACTIVATION_FAILED"})
		return
	}
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeRulePack(w http.ResponseWriter, r *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	if err := s.ruleStore.Remove(r.PathValue("version")); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_REMOVAL_FAILED"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const ModelManifestHeader = "X-AgentVeil-Model-Manifest"

type modelInventory struct {
	Active   string                `json:"active,omitempty"`
	Versions []modelstore.Manifest `json:"versions"`
	Runtime  struct {
		Connected     bool                            `json:"connected"`
		Required      bool                            `json:"required"`
		Active        bool                            `json:"active"`
		ArtifactBytes int64                           `json:"artifact_bytes,omitempty"`
		ResourceState string                          `json:"resource_state"`
		Resources     *detector.SemanticResourceUsage `json:"resources,omitempty"`
	} `json:"runtime"`
}

func (s *Server) listModels(w http.ResponseWriter, _ *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	versions, err := s.modelStore.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_INVENTORY_FAILED"})
		return
	}
	inventory := modelInventory{Versions: versions}
	file, active, err := s.modelStore.OpenActive()
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_MODEL_INVALID"})
			return
		}
		inventory.Active = active.Version
		inventory.Runtime.ArtifactBytes = active.Size
	} else if !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_MODEL_INVALID"})
		return
	}
	inventory.Runtime.Connected = s.semanticLoader != nil
	inventory.Runtime.Required = s.semanticRequired
	inventory.Runtime.Active = inventory.Active != "" && inventory.Active == s.semanticVersion && s.semantic != nil
	inventory.Runtime.ResourceState = "inactive"
	if inventory.Runtime.Active {
		inventory.Runtime.ResourceState = "unreported"
		if reporter, ok := s.semantic.(detector.SemanticResourceReporter); ok {
			usage, usageErr := readSemanticResourceUsage(reporter)
			if usageErr != nil {
				inventory.Runtime.ResourceState = "unavailable"
			} else {
				inventory.Runtime.ResourceState = "reported"
				inventory.Runtime.Resources = &usage
			}
		}
	}
	writeJSON(w, http.StatusOK, inventory)
}

func readSemanticResourceUsage(reporter detector.SemanticResourceReporter) (usage detector.SemanticResourceUsage, err error) {
	defer func() {
		if recover() != nil {
			usage = detector.SemanticResourceUsage{}
			err = domain.NewError(domain.ErrDetectorFailure, "read semantic resource usage", "semantic runtime panicked")
		}
	}()
	usage, err = reporter.SemanticResourceUsage()
	if err != nil {
		return detector.SemanticResourceUsage{}, domain.NewError(domain.ErrDetectorFailure, "read semantic resource usage", "semantic runtime metrics are unavailable")
	}
	if err := usage.Validate(); err != nil {
		return detector.SemanticResourceUsage{}, err
	}
	return usage, nil
}

func (s *Server) installModel(w http.ResponseWriter, r *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	manifest, err := decodeModelUpload(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_MODEL"})
		return
	}
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(maxModelUploadDuration)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_UPLOAD_FAILED"})
		return
	}
	if err := s.modelStore.Install(manifest, r.Body); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_INSTALLATION_FAILED"})
		return
	}
	writeJSON(w, http.StatusCreated, manifest)
}

func (s *Server) activateModel(w http.ResponseWriter, r *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	var request struct {
		Version string `json:"version"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_MODEL_VERSION"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	var semantic detector.Semantic
	if s.semanticLoader != nil {
		file, manifest, err := s.modelStore.Open(request.Version)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
			return
		}
		semantic, err = s.semanticLoader.Load(file, manifest)
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil || semantic == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
			return
		}
	}
	scanner, err := s.buildScannerLocked(semantic, s.semanticRequired)
	if err != nil || s.modelStore.Activate(request.Version) != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
		return
	}
	s.semantic = semantic
	s.semanticVersion = ""
	if semantic != nil {
		s.semanticVersion = request.Version
	}
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deactivateModel(w http.ResponseWriter, _ *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	scanner, err := s.buildScannerLocked(nil, s.semanticRequired)
	if err != nil || s.modelStore.Deactivate() != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_DEACTIVATION_FAILED"})
		return
	}
	s.semantic = nil
	s.semanticVersion = ""
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeModel(w http.ResponseWriter, r *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	if err := s.modelStore.Remove(r.PathValue("version")); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_REMOVAL_FAILED"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentScanner() detector.ContentScanner {
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	return s.scanner
}

func (s *Server) buildScannerLocked(semantic detector.Semantic, semanticRequired bool) (*detector.ChunkedScanner, error) {
	base := detector.NewDefault()
	if s.ruleStore != nil {
		pack, _, err := s.ruleStore.OpenActive()
		if err == nil {
			base, err = detector.NewDefaultWithRulePack(pack)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	base.WithSemantic(semantic, semanticRequired)
	return detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
}

func (s *Server) getCallTree(w http.ResponseWriter, _ *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	owners := map[string]registry.CallSurface{}
	for _, entry := range s.registry.List() {
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
func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	var document policy.Document
	if err := decodeManagement(r, &document); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_POLICY"})
		return
	}
	engine, err := document.Engine()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_POLICY"})
		return
	}
	s.policyMu.Lock()
	store := s.policyStore
	if store == nil {
		s.policyMu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "POLICY_STORE_UNAVAILABLE"})
		return
	}
	if err := store.Save(document); err != nil {
		s.policyMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "POLICY_SAVE_FAILED"})
		return
	}
	s.policy = engine
	s.policyMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) policyEngine() policy.Engine {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return policy.Engine{Default: s.policy.Default, Rules: append([]policy.Rule(nil), s.policy.Rules...)}
}
func (s *Server) resolveApproval(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Action domain.Action `json:"action"`
	}
	if err := decodeManagement(r, &request); err != nil || !s.broker.Resolve(r.PathValue("id"), request.Action) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_APPROVAL"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "DASHBOARD_NONCE_FAILED"})
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
	page := strings.Replace(dashboardHTML, "<style>", `<style nonce="`+nonce+`">`, 1)
	page = strings.Replace(page, "<script>", `<script nonce="`+nonce+`">`, 1)
	page = strings.Replace(page, dashboardAPIVersionPlaceholder, APIVersion, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	secureCoreResponseHeaders(w.Header())
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	_, _ = io.WriteString(w, page)
}

func (s *Server) listAgents(w http.ResponseWriter, _ *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	writeJSON(w, http.StatusOK, s.registry.List())
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	entry, ok := s.registry.Get(r.PathValue("id"))
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
	generationValue := r.URL.Query().Get("generation")
	if generationValue != "" {
		generation, err := strconv.ParseUint(generationValue, 10, 64)
		if err != nil || generation == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_INTEGRATION_GENERATION"})
			return
		}
		if !s.registry.RemoveGeneration(r.PathValue("id"), generation) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "STALE_INTEGRATION_GENERATION"})
			return
		}
	} else {
		s.registry.Remove(r.PathValue("id"))
	}
	w.WriteHeader(http.StatusNoContent)
}

const dashboardAPIVersionPlaceholder = "__AGENTVEIL_API_VERSION__"

const dashboardHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentVeil</title><style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui;background:#0b0e14;color:#e8edf5}body{max-width:1100px;margin:0 auto;padding:40px 24px}h1{letter-spacing:-.04em}.muted{color:#8c98aa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}.card{background:#141925;border:1px solid #273044;border-radius:14px;padding:18px}.route{padding:10px 0;border-top:1px solid #273044}.call{margin:8px 0}.depth-0{margin-left:0}.depth-1{margin-left:24px}.depth-2{margin-left:48px}.depth-3{margin-left:72px}.depth-4{margin-left:96px}.depth-5{margin-left:120px}.depth-6{margin-left:144px}.depth-7{margin-left:168px}.depth-8{margin-left:192px}.status{font-weight:700;text-transform:uppercase}.active,.protected,.local,.low,.allow,.redact{color:#55d89b}.blocked,.unprotected,.error,.critical,.high,.block{color:#ff6b76}.partial,.observed,.medium,.ask{color:#f2bd5a}button,input,textarea,select{background:#1e2635;color:inherit;border:1px solid #35415a;border-radius:8px;padding:10px}button{cursor:pointer}button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #8bc5ff;outline-offset:3px}textarea{box-sizing:border-box;width:100%;min-height:150px;font:13px ui-monospace,monospace;resize:vertical}.controls{display:flex;gap:10px;align-items:center;margin-top:10px}.scope-inputs{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:10px 0}.scope-inputs input{min-width:0}.locale-picker{display:flex;gap:8px;align-items:center;float:right}.skip{position:absolute;left:12px;top:-80px;background:#e8edf5;color:#0b0e14;padding:10px;z-index:10}.skip:focus{top:12px}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}</style></head><body>
<a class="skip" href="#main">Skip to main content</a><main id="main" tabindex="-1"><h1>AgentVeil</h1><p class="muted">Local privacy control plane</p><div><input id="token" type="password" autocomplete="off" aria-label="Management token" placeholder="Management token"><button id="load">Load status</button></div><p id="message" class="muted"></p><div id="approvals" class="grid"></div><h2>Installed agents</h2><div id="discovered" class="grid"></div><h2>Inspection preview</h2><div id="inspection"><p class="muted">Select an installed agent to inspect its surfaces without taking control.</p></div><h2>Registered protection</h2><div id="agents" class="grid"></div><h2>Routing graph</h2><div id="routes" class="grid"></div><h2>Active call tree</h2><div id="calls"></div><h2>Policy</h2><section class="card"><textarea id="policy" spellcheck="false" aria-label="Policy JSON"></textarea><div class="controls"><button id="save-policy">Validate and save</button><span id="policy-result" class="muted"></span></div></section><h2>Rule packs</h2><div id="rule-packs"><p class="muted">Load status to inspect verified rule packs.</p></div><section class="card"><textarea id="rule-manifest" spellcheck="false" aria-label="Signed rule manifest JSON" placeholder="Paste the signed rule manifest JSON"></textarea><div class="controls"><input id="rule-artifact" type="file" accept="application/json,.json" aria-label="Rule pack JSON file"><button id="install-rule">Verify and install</button><span id="rule-install-result" class="muted"></span></div></section><h2>Semantic models</h2><div id="models"><p class="muted">Load status to inspect verified semantic models.</p></div><section class="card"><textarea id="model-manifest" spellcheck="false" aria-label="Signed model manifest JSON" placeholder="Paste the signed model manifest JSON"></textarea><div class="controls"><input id="model-artifact" type="file" accept=".onnx,application/octet-stream" aria-label="ONNX model file"><button id="install-model">Verify and install model</button><span id="model-install-result" class="muted"></span></div></section><h2>Rule test</h2><section class="card"><p id="rule-test-help" class="muted">Preview the current layered policy for each local finding. ASK is shown as an interactive preview; non-interactive runtime requests fail closed. False-positive reports stay on this device and contain metadata only.</p><div class="scope-inputs"><input id="test-agent" autocomplete="off" placeholder="Agent ID (optional)" aria-label="Policy test agent ID"><input id="test-provider" autocomplete="off" placeholder="Provider host (optional)" aria-label="Policy test Provider host"><input id="test-surface" autocomplete="off" placeholder="Surface ID (optional)" aria-label="Policy test Surface ID"><input id="test-workspace" autocomplete="off" placeholder="sha256: workspace reference (optional)" aria-label="Policy test hashed workspace reference"></div><textarea id="test-input" spellcheck="false" autocomplete="off" aria-describedby="rule-test-help" aria-label="Sensitive test input" placeholder="Test input is processed locally and cleared after scanning"></textarea><div class="controls"><button id="test-rules">Scan and preview policy</button><span id="test-result" class="muted"></span></div><div id="test-findings"></div></section><h2>Today and 7-day risk trend</h2><div id="trends" class="grid"></div><h2>Recent decisions</h2><div id="audit" class="grid"></div><h2>Local diagnostics</h2><section class="card"><p class="muted">Exports bounded metadata after field-level and final-payload privacy scans. Routes, paths, credentials, and request content are omitted.</p><div class="controls"><button id="download-diagnostics">Export privacy-safe diagnostics</button><span id="diagnostic-result" class="muted"></span></div></section></main>
<script>
const e=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),token=()=>document.querySelector('#token').value;
const dashboardAPIVersion='__AGENTVEIL_API_VERSION__',browserFetch=window.fetch.bind(window),fetch=async(resource,init={})=>{const headers=new Headers(init.headers||{});headers.set('X-AgentVeil-API-Version',dashboardAPIVersion);const response=await browserFetch(resource,{...init,headers});if(response.headers.get('X-AgentVeil-API-Version')!==dashboardAPIVersion)throw Error('incompatible Core management API');return response};
const translations={"zh-CN":{
"Language":"语言","Skip to main content":"跳到主要内容","Local privacy control plane":"本地隐私控制平面","Management token":"管理令牌","Load status":"加载状态","How protection states work":"保护状态说明","Protected means Core inspects requests, responses, and streams locally. Local means this Surface has no remote transport; child-process networking is separate.":"Protected 表示 Core 在本地检查请求、响应和流。Local 表示此出口没有远程传输；子进程联网需单独判断。","Partial or Observed is not content protection. Some traffic cannot be safely rewritten or is only visible. Unprotected means there is no verified inspection route and must never be treated as protected.":"Partial 或 Observed 不等于内容保护：部分流量无法安全改写或只能观察。Unprotected 表示没有已验证的检查路由，绝不能视为已保护。","Sensitive mappings stay in request-scoped memory. Audit, diagnostics, and false-positive feedback retain bounded metadata only. Detection reduces risk but is not a guarantee of complete anonymization or compliance.":"敏感映射仅保存在请求级内存中。审计、诊断和误报反馈只保留有界元数据。检测用于降低风险，但不保证完全匿名化或合规认证。","Installed agents":"已安装 Agent","Inspection preview":"检查预览","Select an installed agent to inspect its surfaces without taking control.":"选择已安装的 Agent，在不接管的情况下检查其出口。","Registered protection":"已注册保护","Routing graph":"路由图","Active call tree":"活动调用树","Policy":"策略","Policy JSON":"策略 JSON","Validate and save":"校验并保存","Rule packs":"规则包","Load status to inspect verified rule packs.":"加载状态以检查已验证的规则包。","Signed rule manifest JSON":"已签名规则清单 JSON","Paste the signed rule manifest JSON":"粘贴已签名的规则清单 JSON","Rule pack JSON file":"规则包 JSON 文件","Verify and install":"验证并安装","Semantic models":"语义模型","Load status to inspect verified semantic models.":"加载状态以检查已验证的语义模型。","Signed model manifest JSON":"已签名模型清单 JSON","Paste the signed model manifest JSON":"粘贴已签名的模型清单 JSON","ONNX model file":"ONNX 模型文件","Verify and install model":"验证并安装模型","Rule test":"规则测试","Preview the current layered policy for each local finding. ASK is shown as an interactive preview; non-interactive runtime requests fail closed. False-positive reports stay on this device and contain metadata only.":"为每个本地发现预览当前分层策略。ASK 按交互式预览显示；非交互运行时会安全阻断。误报反馈仅保存在本机且只含元数据。","Agent ID (optional)":"Agent ID（可选）","Policy test agent ID":"策略测试 Agent ID","Provider host (optional)":"Provider 主机（可选）","Policy test Provider host":"策略测试 Provider 主机","Surface ID (optional)":"出口 ID（可选）","Policy test Surface ID":"策略测试出口 ID","sha256: workspace reference (optional)":"sha256: 工作区引用（可选）","Policy test hashed workspace reference":"策略测试工作区哈希引用","Sensitive test input":"敏感测试输入","Test input is processed locally and cleared after scanning":"测试输入仅在本地处理，并在扫描后清除","Scan and preview policy":"扫描并预览策略","Today and 7-day risk trend":"今日及 7 天风险趋势","Recent decisions":"最近决策","Local diagnostics":"本地诊断","Exports bounded metadata after field-level and final-payload privacy scans. Routes, paths, credentials, and request content are omitted.":"导出经过字段级与最终载荷隐私扫描的有界元数据，不包含路由、路径、凭据和请求内容。","Export privacy-safe diagnostics":"导出隐私安全诊断","Activate":"启用","Remove":"移除","Select":"选择","Deactivate model":"停用模型","Use built-in rules":"使用内置规则","Mark false positive":"标记误报","Reported locally":"已在本机记录","Feedback failed":"反馈失败","Inspect surfaces":"检查出口","Redact once":"本次脱敏","Allow once":"本次允许","Cancel and block":"取消并阻断","Decision required":"需要决策","Safe preview:":"安全预览：","No deterministic findings":"未发现确定性匹配","No supported agents found":"未发现受支持的 Agent","No registered routes":"没有已注册路由","No active sessions":"没有活动会话","Risks and actions":"风险与操作","Today":"今日","Recent metadata trend":"近期元数据趋势"}};
const messages={en:{
'summary.load':'{installed} installed · {registered} registered · {sessions} active sessions · {decisions} retained decisions','summary.coverage':'Protected {protected} · Local {local} · Partial {partial} · Observed {observed} · Unprotected {unprotected}','risk.detail':'Source {surface} · Impact: {impact} · Action: {action}','trend.day':'{decisions} decisions · {findings} findings · {blocked} blocked/errors','trend.today':'{decisions} decisions · {findings} findings · {errors} errors','trend.actions':'Allow {allow} · Redact {redact} · Block {block} · Ask {ask}','route.flow':'{type} → {protocol} → policy {policy} → {endpoint} → auth {auth} → network {network}','call.session':'Session {session} · {mode} · expires {expires}','call.route':'Route {route} · {protocol} · policy {policy}','call.audit':'Audit {events} events · {findings} findings · last {action} at {time}','call.none':'No retained audit events','health':'Core {status} · API {api} · audit {audit}{failures} · semantic {semantic}','health.failures':' ({count} failures)','test.summary':'{count} findings with policy decisions; input cleared','test.location':'bytes {start}–{end}','test.details':'Rule {rule} · {detector} · {confidence}% confidence · detector suggests {action}','preview':'[REDACTED:{category}] replaces {bytes} bytes','approval.preview':'Safe preview: {preview}','audit.row':'{findings} findings · {latency} ms','mode.interactive':'interactive','mode.noninteractive':'non-interactive','scope.default':'default policy','scope.all':'all findings','rule.secret':'Deterministic credential or secret signature','rule.pii':'PII format, validator, or local semantic classification','rule.pack':'Verified local rule-pack classification'},
'zh-CN':{
'summary.load':'已安装 {installed} 个 · 已注册 {registered} 个 · 活动会话 {sessions} 个 · 保留决策 {decisions} 条','summary.coverage':'已保护 {protected} · 本地 {local} · 部分 {partial} · 已观察 {observed} · 未保护 {unprotected}','risk.detail':'来源 {surface} · 影响：{impact} · 操作：{action}','trend.day':'{decisions} 条决策 · {findings} 个发现 · {blocked} 条阻断/错误','trend.today':'{decisions} 条决策 · {findings} 个发现 · {errors} 个错误','trend.actions':'放行 {allow} · 脱敏 {redact} · 阻断 {block} · 询问 {ask}','route.flow':'{type} → {protocol} → 策略 {policy} → {endpoint} → 认证 {auth} → 网络 {network}','call.session':'会话 {session} · {mode} · 到期 {expires}','call.route':'路由 {route} · {protocol} · 策略 {policy}','call.audit':'审计 {events} 条事件 · {findings} 个发现 · 最近 {action} 于 {time}','call.none':'没有保留的审计事件','health':'Core {status} · API {api} · 审计 {audit}{failures} · 语义能力 {semantic}','health.failures':'（{count} 次失败）','test.summary':'发现 {count} 项并完成策略预览；输入已清除','test.location':'字节 {start}–{end}','test.details':'规则 {rule} · {detector} · 置信度 {confidence}% · 检测器建议 {action}','preview':'[已脱敏：{category}] 替换 {bytes} 字节','approval.preview':'安全预览：{preview}','audit.row':'{findings} 个发现 · {latency} 毫秒','mode.interactive':'交互','mode.noninteractive':'非交互','scope.default':'默认策略','scope.all':'全部发现','rule.secret':'确定性凭据或 Secret 特征','rule.pii':'PII 格式、校验器或本地语义分类','rule.pack':'已验证的本地规则包分类'}};
Object.assign(translations['zh-CN'],{
'unknown Surface':'未知出口','Protection cannot be proven':'无法证明保护有效','No coverage result':'无覆盖结果','Policy decision unavailable':'策略决策不可用','Core health unavailable':'Core 健康状态不可用','Inspection unavailable; no control changes were made.':'检查不可用；未更改任何控制状态。','Unable to load protected status':'无法加载保护状态','request, response and stream inspection are available':'请求、响应和流检查均可用','surface uses local stdio; descendant network egress is separate':'出口使用本地 stdio；子进程网络出口需单独判断','unknown surfaces and protocols fail closed':'未知出口或协议将安全阻断','no protocol capability is registered':'没有已注册的协议能力','traffic can be observed but the surface cannot be safely rewritten':'可以观察流量，但无法安全改写该出口','surface cannot be safely rewritten':'无法安全改写该出口','request content is not inspectable':'无法检查请求内容','request inspection is available but response or stream protection is incomplete':'可检查请求，但响应或流保护不完整','routing graph contains a content modifier after AgentVeil':'路由图中 AgentVeil 之后存在内容修改器','content-modifying middleware appears after AgentVeil':'内容修改中间件位于 AgentVeil 之后','unexpected process egress was observed outside protected routes':'在受保护路由之外观察到意外进程出口','process egress was blocked before bypassing protected routes':'进程出口已在绕过受保护路由前阻断','Disable the Surface or add a verified adapter':'停用该出口或添加已验证适配器','Block the route until its protocol is supported':'在协议受支持前阻断该路由','Block the Surface or use a scoped transparent integration':'阻断该出口或使用限定范围的透明集成','Block response streaming or add complete response protection':'阻断响应流或补全响应保护','Disable streaming or add a verified stream adapter':'停用流式传输或添加已验证流适配器','Block the Surface or select a content-protected integration':'阻断该出口或选择内容受保护的集成','Disable the Surface or install a compatible capability':'停用该出口或安装兼容能力','Move the content modifier before AgentVeil or block the route':'将内容修改器移到 AgentVeil 之前或阻断路由','Terminate the process tree and investigate the unplanned exit':'终止进程树并调查计划外出口','Keep the Surface blocked until the risk is resolved':'风险解决前保持该出口阻断','ASK fails closed in a non-interactive context':'非交互环境中的 ASK 将安全阻断','default policy':'默认策略','most specific matching rule':'最具体的匹配规则','explicit matching block rule':'显式匹配的阻断规则','Scan or policy preview rejected; input cleared':'扫描或策略预览被拒绝；输入已清除'});
Object.assign(translations['zh-CN'],{'active':'活动','verified':'已验证','selected':'已选择','built-in':'内置','protected':'已保护','local':'本地','partial':'部分保护','observed':'已观察','unprotected':'未保护','blocked':'已阻断','allow':'放行','redact':'脱敏','block':'阻断','ask':'询问','unknown version':'未知版本','Signed rule storage is not configured.':'未配置签名规则存储。','Signed semantic-model storage is not configured.':'未配置签名语义模型存储。','Policy saved atomically':'策略已原子保存','Policy rejected; check JSON, actions, and scoped identifiers':'策略被拒绝；请检查 JSON、动作和 Scope 标识','Signed rule pack installed but not activated':'签名规则包已安装但未启用','Installation rejected; verify manifest, signature, and file size':'安装被拒绝；请检查清单、签名和文件大小','Signed model installed but not selected':'签名模型已安装但未选择','Installation rejected; verify manifest, signature, digest, and file size':'安装被拒绝；请检查清单、签名、摘要和文件大小','Privacy-safe diagnostics exported locally':'隐私安全诊断已导出到本机','Diagnostic export failed':'诊断导出失败','Unable to load policy':'无法加载策略','Rule inventory unavailable.':'规则清单不可用。','Model inventory unavailable.':'模型清单不可用。','Rule activation failed.':'规则启用失败。','Rule removal failed.':'规则移除失败。','Rule deactivation failed.':'规则停用失败。','Model selection failed.':'模型选择失败。','Model removal failed.':'模型移除失败。','Model deactivation failed.':'模型停用失败。'});
Object.assign(messages.en,{'model.active':'Semantic inference is active for the selected model','model.required':'Semantic inference is required; requests fail closed until a compatible model is active','model.ready':'Local semantic runtime connected; no model is active','model.disconnected':'A selected artifact is verified storage state; semantic inference remains unavailable until the local runtime is connected','model.resources':'Runtime resources: {resident} resident · {workers} workers · {accelerator} · {inferences} inferences','model.resourceUnavailable':'Runtime resource metrics are temporarily unavailable','model.resourceUnreported':'Active runtime does not report resource metrics','model.resourceInactive':'Runtime resources are inactive','model.artifact':' · selected artifact {size}','artifact.version':'{version} · {size} bytes','model.selected':'selected {version}','model.none':'no model selected'});
Object.assign(messages['zh-CN'],{'model.active':'已选模型的语义推理正在运行','model.required':'语义推理为必需能力；兼容模型启用前请求将安全阻断','model.ready':'本地语义运行时已连接；当前没有启用模型','model.disconnected':'已选制品仅代表存储已验证；连接本地运行时前语义推理仍不可用','model.resources':'运行资源：常驻 {resident} · {workers} 个工作线程 · {accelerator} · {inferences} 次推理','model.resourceUnavailable':'运行资源指标暂时不可用','model.resourceUnreported':'活动运行时未报告资源指标','model.resourceInactive':'运行资源未启用','model.artifact':' · 已选制品 {size}','artifact.version':'{version} · {size} 字节','model.selected':'已选择 {version}','model.none':'未选择模型'});
Object.assign(messages.en,{'rule.verified':'verified {version}','rule.builtin':'built-in','confirm.rule':'Remove inactive rule pack {version}?','confirm.model':'Remove inactive semantic model {version}?'});
Object.assign(messages['zh-CN'],{'rule.verified':'已验证 {version}','rule.builtin':'内置规则','confirm.rule':'移除未启用的规则包 {version}？','confirm.model':'移除未启用的语义模型 {version}？'});
let dashboardLocale=(()=>{try{const saved=localStorage.getItem('agentveil.locale');if(saved==='en'||saved==='zh-CN')return saved}catch(err){}return String(navigator.language||'en').toLowerCase().startsWith('zh')?'zh-CN':'en'})();
const textOriginals=new WeakMap(),attributeOriginals=new WeakMap();
function localizedText(value){return dashboardLocale==='zh-CN'&&(translations['zh-CN'][value]||value)||value}
function message(key,values={}){const catalog=messages[dashboardLocale]||messages.en,template=catalog[key]||messages.en[key]||key;return template.replace(/\{([a-z_]+)\}/g,(_,name)=>String(values[name]??''))}
function translateTree(root){const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);for(let node=walker.nextNode();node;node=walker.nextNode()){if(['SCRIPT','STYLE','TEXTAREA'].includes(node.parentElement&&node.parentElement.tagName))continue;if(!textOriginals.has(node))textOriginals.set(node,node.nodeValue);const original=textOriginals.get(node),trimmed=original.trim(),translated=localizedText(trimmed),next=original.replace(trimmed,translated);if(node.nodeValue!==next)node.nodeValue=next}const elements=(root.querySelectorAll?[root,...root.querySelectorAll('[placeholder],[aria-label],[title]')]:[]);for(const element of elements){let originals=attributeOriginals.get(element);if(!originals){originals={};attributeOriginals.set(element,originals)}for(const attribute of ['placeholder','aria-label','title']){if(!element.hasAttribute||!element.hasAttribute(attribute))continue;if(!(attribute in originals))originals[attribute]=element.getAttribute(attribute);const next=localizedText(originals[attribute]);if(element.getAttribute(attribute)!==next)element.setAttribute(attribute,next)}}document.documentElement.lang=dashboardLocale}
const localeBox=document.createElement('label');localeBox.className='locale-picker';localeBox.append(document.createTextNode('Language'));const localeChoice=document.createElement('select');localeChoice.setAttribute('aria-label','Language');for(const option of [['en','English'],['zh-CN','简体中文']]){const node=document.createElement('option');node.value=option[0];node.textContent=option[1];localeChoice.append(node)}localeChoice.value=dashboardLocale;localeBox.append(localeChoice);document.querySelector('h1').before(localeBox);translateTree(document);
const localeObserver=new MutationObserver(records=>{for(const record of records)for(const node of record.addedNodes){const target=node.nodeType===Node.ELEMENT_NODE?node:node.nodeType===Node.TEXT_NODE?node.parentElement:null;if(target)translateTree(target)}});localeObserver.observe(document.querySelector('#main'),{childList:true,subtree:true});
localeChoice.onchange=()=>{dashboardLocale=localeChoice.value;try{localStorage.setItem('agentveil.locale',dashboardLocale)}catch(err){}translateTree(document);if(token())document.querySelector('#load').click()};
let lastTestResults=[];
const healthNode=document.createElement('p');healthNode.id='core-health';healthNode.className='muted';document.querySelector('#message').after(healthNode);
const safetyGuide=document.createElement('details');safetyGuide.className='card';safetyGuide.innerHTML='<summary>How protection states work</summary><p>Protected means Core inspects requests, responses, and streams locally. Local means this Surface has no remote transport; child-process networking is separate.</p><p>Partial or Observed is not content protection. Some traffic cannot be safely rewritten or is only visible. Unprotected means there is no verified inspection route and must never be treated as protected.</p><p class="muted">Sensitive mappings stay in request-scoped memory. Audit, diagnostics, and false-positive feedback retain bounded metadata only. Detection reduces risk but is not a guarantee of complete anonymization or compliance.</p>';healthNode.after(safetyGuide);translateTree(safetyGuide);
for(const id of ['message','core-health','policy-result','rule-install-result','model-install-result','test-result','diagnostic-result']){const node=document.querySelector('#'+id);node.setAttribute('role','status');node.setAttribute('aria-live','polite')}
async function decide(id,action){await fetch('/v1/approvals/'+id,{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({action})});await load()}
function endpointText(upstream){upstream=upstream||{};return(upstream.scheme||'unknown')+'://'+(upstream.host||'unknown')+(upstream.port?':'+Number(upstream.port):'')+(upstream.path||'')}
function riskAction(code){return({UNKNOWN_SURFACE:'Disable the Surface or add a verified adapter',UNKNOWN_PROTOCOL:'Block the route until its protocol is supported',SURFACE_NOT_REWRITABLE:'Block the Surface or use a scoped transparent integration',REQUEST_ONLY_PROTECTION:'Block response streaming or add complete response protection',STREAM_UNSUPPORTED:'Disable streaming or add a verified stream adapter',OBSERVED_ONLY:'Block the Surface or select a content-protected integration',UNSUPPORTED_CAPABILITY:'Disable the Surface or install a compatible capability',CONTENT_MODIFIER_AFTER_DLP:'Move the content modifier before AgentVeil or block the route',UNEXPECTED_EGRESS:'Terminate the process tree and investigate the unplanned exit'})[code]||'Keep the Surface blocked until the risk is resolved'}
function renderRisks(risks){return(risks||[]).map(risk=>'<div class="route"><span class="status '+e(risk.severity||'high')+'">'+e(risk.severity||'high')+'</span> · '+e(risk.code||'UNKNOWN_RISK')+'<br><span class="muted">'+e(message('risk.detail',{surface:risk.surface_id||localizedText('unknown Surface'),impact:localizedText(risk.message||'Protection cannot be proven'),action:localizedText(riskAction(risk.code))}))+'</span></div>').join('')}
function localDay(value){const date=new Date(value);return Number.isNaN(date.getTime())?'':date.getFullYear()+'-'+String(date.getMonth()+1).padStart(2,'0')+'-'+String(date.getDate()).padStart(2,'0')}
function renderTrends(events){const now=new Date(),today=localDay(now),todayEvents=(events||[]).filter(event=>localDay(event.timestamp)===today),actions={allow:0,redact:0,block:0,ask:0};let findings=0,errors=0;for(const event of todayEvents){if(Object.hasOwn(actions,event.action))actions[event.action]++;findings+=Number(event.finding_count||0);if(event.error_code)errors++}const days=[];for(let offset=6;offset>=0;offset--){const day=new Date(now);day.setHours(12,0,0,0);day.setDate(day.getDate()-offset);const key=localDay(day),matching=(events||[]).filter(event=>localDay(event.timestamp)===key);days.push('<p>'+e(key)+' · '+e(message('trend.day',{decisions:matching.length,findings:matching.reduce((total,event)=>total+Number(event.finding_count||0),0),blocked:matching.filter(event=>event.action==='block'||event.error_code).length}))+'</p>')}return'<section class="card"><h2>'+e(localizedText('Today'))+'</h2><p>'+e(message('trend.today',{decisions:todayEvents.length,findings,errors}))+'</p><p class="muted">'+e(message('trend.actions',actions))+'</p></section><section class="card"><h2>'+e(localizedText('Recent metadata trend'))+'</h2>'+days.join('')+'</section>'}
function renderRoutes(rows){return rows.map(entry=>{const routes=Object.fromEntries((entry.plan.routes||[]).map(route=>[route.surface_id,route])),coverage=Object.fromEntries((entry.plan.coverage||[]).map(item=>[item.surface_id,item]));return'<section class="card"><h2>'+e(entry.manifest.agent.kind)+'</h2>'+(entry.manifest.surfaces||[]).map(surface=>{const route=routes[surface.id],status=coverage[surface.id]||{status:'unprotected',reason:'No coverage result'},upstream=route&&route.upstream||surface.upstream||{},auth=route&&route.auth||surface.auth||{},network=route&&route.network||surface.network||{},policy=route&&route.policy_id||'none';return'<div class="route"><span class="status '+e(status.status)+'">'+e(status.status)+'</span> · '+e(surface.name)+'<br><span class="muted">'+e(message('route.flow',{type:surface.type,protocol:route&&route.protocol||surface.protocol||'unknown',policy,endpoint:endpointText(upstream),auth:auth.type||'unknown',network:network.type||'unknown'}))+'</span><br><span class="muted">'+e(localizedText(status.reason||''))+'</span></div>'}).join('')+'</section>'}).join('')}
function renderCalls(tree,parent,depth){return(tree[parent]||[]).map(node=>'<div class="card call depth-'+Math.min(depth,8)+'"><div class="muted">'+e(message('call.session',{session:node.session_id,mode:message(node.interactive?'mode.interactive':'mode.noninteractive'),expires:node.expires_at}))+'</div>'+node.surfaces.map(surface=>'<div><span class="status '+e(surface.coverage)+'">'+e(surface.coverage)+'</span> · '+e(surface.agent_id||'unregistered')+' / '+e(surface.surface_id||'unknown surface')+'<br><span class="muted">'+e(message('call.route',{route:surface.route_id,protocol:surface.protocol||'unknown protocol',policy:surface.policy_id||'unavailable'}))+'</span></div>').join('')+(node.audit?'<p class="muted">'+e(message('call.audit',{events:Number(node.audit.event_count||0),findings:Number(node.audit.finding_count||0),action:node.audit.last_action||'none',time:node.audit.last_at||'unknown'}))+'</p>':'<p class="muted">'+e(message('call.none'))+'</p>')+'</div>'+renderCalls(tree,node.session_id,depth+1)).join('')}
async function loadPolicy(){const response=await fetch('/v1/policy',{headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('policy unavailable');if(document.activeElement!==document.querySelector('#policy'))document.querySelector('#policy').value=JSON.stringify(await response.json(),null,2)}
async function savePolicy(){const result=document.querySelector('#policy-result');try{const source=document.querySelector('#policy').value;JSON.parse(source);const response=await fetch('/v1/policy',{method:'PUT',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:source});if(!response.ok)throw Error('invalid policy');result.className='active';result.textContent='Policy saved atomically'}catch(err){result.className='error';result.textContent='Policy rejected; check JSON, actions, and scoped identifiers'}}
function byteSize(value){value=Number(value||0);if(value<1024)return value+' B';if(value<1048576)return(value/1024).toFixed(1)+' KiB';if(value<1073741824)return(value/1048576).toFixed(1)+' MiB';return(value/1073741824).toFixed(1)+' GiB'}
async function loadRulePacks(){const output=document.querySelector('#rule-packs'),response=await fetch('/v1/rules',{headers:{Authorization:'Bearer '+token()}});if(response.status===503){output.innerHTML='<p class="muted">Signed rule storage is not configured.</p>';return}if(!response.ok)throw Error('rule inventory unavailable');const inventory=await response.json(),active=inventory.active||'';output.innerHTML='<section class="card"><p><span class="status '+(active?'active':'local')+'">'+e(active?message('rule.verified',{version:active}):message('rule.builtin'))+'</span></p><div class="controls"><button id="use-built-in" '+(active?'':'disabled')+'>Use built-in rules</button></div>'+inventory.versions.map(version=>'<p>'+e(message('artifact.version',{version:version.version,size:Number(version.size)}))+' '+(version.version===active?'<span class="status active">active</span>':'<button class="activate-rule" data-version="'+e(version.version)+'">Activate</button> <button class="remove-rule" data-version="'+e(version.version)+'">Remove</button>')+'</p>').join('')+'</section>'}
async function activateRulePack(version){const response=await fetch('/v1/rules/active',{method:'PUT',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({version})});if(!response.ok)throw Error('activation failed');await loadRulePacks()}
async function deactivateRulePack(){const response=await fetch('/v1/rules/active',{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('deactivation failed');await loadRulePacks()}
async function removeRulePack(version){if(!window.confirm(message('confirm.rule',{version})))return;const response=await fetch('/v1/rules/'+encodeURIComponent(version),{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('removal failed');await loadRulePacks()}
function encodeBase64(bytes){let binary='';for(let offset=0;offset<bytes.length;offset+=32768)binary+=String.fromCharCode(...bytes.subarray(offset,offset+32768));return btoa(binary)}
async function installRulePack(){const result=document.querySelector('#rule-install-result'),manifestInput=document.querySelector('#rule-manifest'),fileInput=document.querySelector('#rule-artifact');try{const file=fileInput.files[0],manifestSource=manifestInput.value;if(!file||file.size<1||file.size>1048576)throw Error('invalid artifact size');JSON.parse(manifestSource);const artifactBase64=encodeBase64(new Uint8Array(await file.arrayBuffer())),body='{"manifest":'+manifestSource+',"artifact_base64":'+JSON.stringify(artifactBase64)+'}',response=await fetch('/v1/rules',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body});fileInput.value='';if(!response.ok)throw Error('installation failed');manifestInput.value='';result.className='active';result.textContent='Signed rule pack installed but not activated';await loadRulePacks()}catch(err){fileInput.value='';result.className='error';result.textContent='Installation rejected; verify manifest, signature, and file size'}}
async function loadModels(){const output=document.querySelector('#models'),response=await fetch('/v1/models',{headers:{Authorization:'Bearer '+token()}});if(response.status===503){output.innerHTML='<p class="muted">Signed semantic-model storage is not configured.</p>';return}if(!response.ok)throw Error('model inventory unavailable');const inventory=await response.json(),active=inventory.active||'',runtime=inventory.runtime||{},resources=runtime.resources||{},runtimeText=message(runtime.active?'model.active':runtime.connected?(runtime.required?'model.required':'model.ready'):'model.disconnected'),resourceText=runtime.resource_state==='reported'?message('model.resources',{resident:byteSize(resources.resident_bytes),workers:Number(resources.worker_count),accelerator:resources.accelerator,inferences:Number(resources.inference_count)}):message(runtime.resource_state==='unavailable'?'model.resourceUnavailable':runtime.resource_state==='unreported'?'model.resourceUnreported':'model.resourceInactive'),artifactText=runtime.artifact_bytes?message('model.artifact',{size:byteSize(runtime.artifact_bytes)}):'';output.innerHTML='<section class="card"><p><span class="status '+(runtime.active?'active':active?'partial':'observed')+'">'+e(active?message('model.selected',{version:active}):message('model.none'))+'</span></p><p class="muted">'+e(runtimeText)+'</p><p class="muted">'+e(resourceText+artifactText)+'</p><div class="controls"><button id="deactivate-model" '+(active?'':'disabled')+'>Deactivate model</button></div>'+inventory.versions.map(version=>'<p>'+e(message('artifact.version',{version:version.version,size:Number(version.size)}))+' '+(version.version===active?'<span class="status '+(runtime.active?'active':'partial')+'">selected</span>':'<button class="activate-model" data-version="'+e(version.version)+'">Select</button> <button class="remove-model" data-version="'+e(version.version)+'">Remove</button>')+'</p>').join('')+'</section>'}
async function activateModel(version){const response=await fetch('/v1/models/active',{method:'PUT',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({version})});if(!response.ok)throw Error('model selection failed');await loadModels()}
async function deactivateModel(){const response=await fetch('/v1/models/active',{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('model deactivation failed');await loadModels()}
async function removeModel(version){if(!window.confirm(message('confirm.model',{version})))return;const response=await fetch('/v1/models/'+encodeURIComponent(version),{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('model removal failed');await loadModels()}
async function installModel(){const result=document.querySelector('#model-install-result'),manifestInput=document.querySelector('#model-manifest'),fileInput=document.querySelector('#model-artifact');try{const file=fileInput.files[0],manifestSource=manifestInput.value,manifest=JSON.parse(manifestSource),manifestBytes=new TextEncoder().encode(manifestSource);if(!file||file.size<1||file.size>536870912||Number(manifest.size)!==file.size||manifestBytes.length<1||manifestBytes.length>6144)throw Error('invalid artifact or manifest size');const encodedManifest=encodeBase64(manifestBytes),response=await fetch('/v1/models',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/octet-stream','X-AgentVeil-Model-Manifest':encodedManifest},body:file});fileInput.value='';if(!response.ok)throw Error('model installation failed');manifestInput.value='';result.className='active';result.textContent='Signed model installed but not selected';await loadModels()}catch(err){fileInput.value='';result.className='error';result.textContent='Installation rejected; verify manifest, signature, digest, and file size'}}
function policyScope(scope){if(!scope)return message('scope.default');return Object.entries(scope).filter(entry=>entry[1]).map(entry=>entry[0]+'='+entry[1]).join(' · ')||message('scope.all')}
function redactionPreview(finding){const location=finding.location||{},length=Math.max(0,Number(location.end||0)-Number(location.start||0));return message('preview',{category:String(finding.category||'sensitive'),bytes:length})}
function ruleExplanation(finding){const category=String(finding.category||'');if(category.startsWith('secret.'))return message('rule.secret');if(category.startsWith('pii.'))return message('rule.pii');return message('rule.pack')}
async function testRules(){const input=document.querySelector('#test-input'),result=document.querySelector('#test-result'),output=document.querySelector('#test-findings'),scope={agent_id:document.querySelector('#test-agent').value,provider:document.querySelector('#test-provider').value,surface_id:document.querySelector('#test-surface').value,workspace:document.querySelector('#test-workspace').value};for(const key of Object.keys(scope))if(!scope[key])delete scope[key];try{const response=await fetch('/v1/detect',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({text:input.value,scope})});input.value='';if(!response.ok)throw Error('scan failed');const payload=await response.json();lastTestResults=payload.results||[];result.className='active';result.textContent=message('test.summary',{count:lastTestResults.length});output.innerHTML=lastTestResults.map((item,index)=>{const finding=item.finding||{},decision=item.decision||{},confidence=Math.max(0,Math.min(100,Math.round(Number(finding.confidence||0)*100)));return'<div class="route"><span class="status '+e(decision.action)+'">'+e(decision.action||'unknown')+'</span> · <span class="status '+e(finding.severity)+'">'+e(finding.severity)+'</span> · '+e(finding.category)+' · '+e(message('test.location',{start:Number(finding.location&&finding.location.start),end:Number(finding.location&&finding.location.end)}))+'<br><span class="muted">'+e(message('test.details',{rule:finding.rule_id||'unknown',detector:finding.detector||'unknown',confidence,action:finding.suggested_action||'unknown'}))+'<br>'+e(ruleExplanation(finding))+'<br>'+e(localizedText(decision.reason||'Policy decision unavailable'))+' · '+e(policyScope(decision.matched_scope))+'</span><div class="controls"><button class="false-positive" data-index="'+index+'">Mark false positive</button></div></div>'}).join('')||'<p class="muted">No deterministic findings</p>'}catch(err){input.value='';lastTestResults=[];output.textContent='';result.className='error';result.textContent=localizedText('Scan or policy preview rejected; input cleared')}}
async function reportFalsePositive(index,button){const item=lastTestResults[index];if(!item)throw Error('feedback expired');const response=await fetch('/v1/feedback/false-positives',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({finding:item.finding,policy_action:item.decision.action,policy_context:item.policy_context})});if(!response.ok)throw Error('feedback rejected');button.disabled=true;button.textContent='Reported locally'}
async function downloadDiagnostics(){const result=document.querySelector('#diagnostic-result');try{const response=await fetch('/v1/diagnostics',{headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('diagnostics unavailable');const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='agentveil-diagnostics.json';link.click();URL.revokeObjectURL(url);result.className='active';result.textContent='Privacy-safe diagnostics exported locally'}catch(err){result.className='error';result.textContent='Diagnostic export failed'}}
async function loadHealth(){try{const response=await fetch('/v1/health',{headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('health unavailable');const health=await response.json(),node=document.querySelector('#core-health'),failures=Number(health.audit_failures||0);node.className='status '+(health.status==='ok'?'active':'error');node.textContent=message('health',{status:health.status||'unknown',api:health.api_version||'unknown',audit:health.audit||'unknown',failures:failures?message('health.failures',{count:failures}):'',semantic:health.semantic||'unknown'})}catch(err){const node=document.querySelector('#core-health');node.className='status error';node.textContent=localizedText('Core health unavailable')}}
async function inspectAgent(name){const output=document.querySelector('#inspection');try{const response=await fetch('/v1/discovery/'+encodeURIComponent(name),{headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('inspection failed');const x=await response.json(),coverage=Object.fromEntries(x.protection_plan.coverage.map(item=>[item.surface_id,item]));output.innerHTML='<section class="card"><h2>'+e(x.manifest.agent.kind)+' <span class="muted">'+e(x.manifest.agent.version)+'</span></h2><p>'+e(message('summary.coverage',x.protection_plan.summary))+'</p>'+x.manifest.surfaces.map(surface=>{const status=coverage[surface.id]||{status:'unprotected',reason:'No coverage result'};return '<p><span class="status '+e(status.status)+'">'+e(status.status)+'</span> · '+e(surface.name)+' · '+e(surface.protocol)+'<br><span class="muted">'+e(localizedText(status.reason))+'</span></p>'}).join('')+(x.protection_plan.risks.length?'<h3>'+e(localizedText('Risks and actions'))+'</h3>'+renderRisks(x.protection_plan.risks):'')+'</section>'}catch(err){output.innerHTML='<p class="error">'+e(localizedText('Inspection unavailable; no control changes were made.'))+'</p>'}}
async function load(){const m=document.querySelector('#message');try{const headers={Authorization:'Bearer '+token()},responses=await Promise.all([fetch('/v1/agents',{headers}),fetch('/v1/approvals',{headers}),fetch('/v1/audit',{headers}),fetch('/v1/call-tree',{headers}),fetch('/v1/discovery',{headers})]);if(responses.some(response=>!response.ok))throw Error('unauthorized');const rows=await responses[0].json(),asks=await responses[1].json(),events=await responses[2].json(),calls=await responses[3].json(),detections=await responses[4].json(),sessionCount=Object.values(calls).reduce((total,nodes)=>total+nodes.length,0);m.textContent=message('summary.load',{installed:detections.length,registered:rows.length,sessions:sessionCount,decisions:events.length});document.querySelector('#approvals').innerHTML=asks.map(x=>'<section class="card"><div class="status partial">Decision required</div><h2>'+e(x.finding.category)+'</h2><p>'+e(x.finding.severity)+' · '+e(x.finding.location.path)+'</p><p class="muted">'+e(message('approval.preview',{preview:redactionPreview(x.finding)}))+'</p><button class="approval-decision" data-id="'+e(x.id)+'" data-action="redact">Redact once</button> <button class="approval-decision" data-id="'+e(x.id)+'" data-action="allow">Allow once</button> <button class="approval-decision" data-id="'+e(x.id)+'" data-action="block">Cancel and block</button></section>').join('');document.querySelector('#discovered').innerHTML=detections.map(x=>'<section class="card"><div class="status '+e(x.status==='verified'?'active':'observed')+'">'+e(x.status)+'</div><h2>'+e(x.agent)+'</h2><p class="muted">'+e(x.version||'unknown version')+'</p><button class="inspect-agent" data-agent="'+e(x.agent)+'">Inspect surfaces</button></section>').join('')||'<p class="muted">No supported agents found</p>';document.querySelector('#agents').innerHTML=rows.map(x=>'<section class="card"><div class="status '+e(x.state)+'">'+e(x.state)+'</div><h2>'+e(x.manifest.agent.kind)+'</h2><p class="muted">'+e(x.manifest.agent.version||'unknown version')+'</p><p>'+e(message('summary.coverage',x.plan.summary))+'</p>'+renderRisks(x.plan.risks)+'</section>').join('');document.querySelector('#routes').innerHTML=renderRoutes(rows)||'<p class="muted">No registered routes</p>';document.querySelector('#calls').innerHTML=renderCalls(calls,'',0)||'<p class="muted">No active sessions</p>';document.querySelector('#trends').innerHTML=renderTrends(events);document.querySelector('#audit').innerHTML=events.slice(-20).reverse().map(x=>'<section class="card"><div class="status '+e(x.action)+'">'+e(x.action)+'</div><p>'+e(x.agent_id||'unknown')+' · '+e(x.surface_id||'unknown')+'</p><p class="muted">'+e(x.protocol||'unknown')+' · '+e(message('audit.row',{findings:Number(x.finding_count||0),latency:Number(x.latency_ms||0)}))+(x.error_code?' · '+e(x.error_code):'')+'</p></section>').join('')}catch(err){m.textContent=localizedText('Unable to load protected status');for(const id of ['discovered','agents','routes','calls','trends','audit'])document.querySelector('#'+id).textContent=''}}
document.querySelector('#load').onclick=()=>{load();loadHealth();loadPolicy().catch(()=>{document.querySelector('#policy-result').textContent='Unable to load policy'});loadRulePacks().catch(()=>{document.querySelector('#rule-packs').innerHTML='<p class="error">Rule inventory unavailable.</p>'});loadModels().catch(()=>{document.querySelector('#models').innerHTML='<p class="error">Model inventory unavailable.</p>'})};document.querySelector('#save-policy').onclick=savePolicy;document.querySelector('#install-rule').onclick=installRulePack;document.querySelector('#install-model').onclick=installModel;document.querySelector('#test-rules').onclick=testRules;document.querySelector('#download-diagnostics').onclick=downloadDiagnostics;setInterval(()=>{if(token()){load();loadHealth()}},1000)
document.querySelector('#discovered').onclick=event=>{const button=event.target.closest('.inspect-agent');if(button)inspectAgent(button.dataset.agent)}
document.querySelector('#approvals').onclick=event=>{const button=event.target.closest('.approval-decision');if(button)decide(button.dataset.id,button.dataset.action)}
document.querySelector('#test-findings').onclick=event=>{const button=event.target.closest('.false-positive');if(button)reportFalsePositive(Number(button.dataset.index),button).catch(()=>{button.textContent='Feedback failed'})}
document.querySelector('#rule-packs').onclick=event=>{const activate=event.target.closest('.activate-rule'),remove=event.target.closest('.remove-rule');if(activate)activateRulePack(activate.dataset.version).catch(()=>{document.querySelector('#rule-packs').innerHTML='<p class="error">Rule activation failed.</p>'});if(remove)removeRulePack(remove.dataset.version).catch(()=>{document.querySelector('#rule-packs').innerHTML='<p class="error">Rule removal failed.</p>'});if(event.target.closest('#use-built-in'))deactivateRulePack().catch(()=>{document.querySelector('#rule-packs').innerHTML='<p class="error">Rule deactivation failed.</p>'})}
document.querySelector('#models').onclick=event=>{const activate=event.target.closest('.activate-model'),remove=event.target.closest('.remove-model');if(activate)activateModel(activate.dataset.version).catch(()=>{document.querySelector('#models').innerHTML='<p class="error">Model selection failed.</p>'});if(remove)removeModel(remove.dataset.version).catch(()=>{document.querySelector('#models').innerHTML='<p class="error">Model removal failed.</p>'});if(event.target.closest('#deactivate-model'))deactivateModel().catch(()=>{document.querySelector('#models').innerHTML='<p class="error">Model deactivation failed.</p>'})}
</script></body></html>`

func (s *Server) Endpoint() string {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener == nil {
		return ""
	}
	return "http://" + s.listener.Addr().String()
}

func (s *Server) Close(ctx context.Context) error {
	s.lifecycleMu.Lock()
	cleanupCancel, cleanupDone, httpServer := s.cleanupCancel, s.cleanupDone, s.httpServer
	s.lifecycleMu.Unlock()
	s.manager.Close()
	if cleanupCancel != nil {
		cleanupCancel()
		<-cleanupDone
	}
	if httpServer == nil {
		return nil
	}
	return httpServer.Shutdown(ctx)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validVersionedLocalRequest(w, r) {
			return
		}
		provided, ok := managementBearer(r.Header.Values("Authorization"))
		if !ok || !secureEqual(provided, s.adminToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "UNAUTHORIZED_MANAGEMENT_API"})
			return
		}
		next(w, r)
	}
}

func validVersionedLocalRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set(APIVersionHeader, APIVersion)
	requestedVersions := r.Header.Values(APIVersionHeader)
	if len(requestedVersions) > 1 || len(requestedVersions) == 1 && requestedVersions[0] != APIVersion {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "INCOMPATIBLE_MANAGEMENT_API"})
		return false
	}
	if !security.ValidLocalOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": string(domain.ErrInvalidOrigin)})
		return false
	}
	return true
}

func validAdminToken(value string) bool {
	if len(value) < minAdminTokenBytes || len(value) > maxAdminTokenBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func managementBearer(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	scheme, credential, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || !validAdminToken(credential) {
		return "", false
	}
	return credential, true
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

func (s *Server) listSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.manager.List())
}

type createRequest struct {
	ParentSessionID string   `json:"parent_session_id"`
	RouteIDs        []string `json:"route_ids"`
	TTLSeconds      int64    `json:"ttl_seconds"`
	Interactive     bool     `json:"interactive"`
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
	for _, entry := range s.registry.List() {
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
	if agentKind == "hermes" {
		return []string{capabilityTransportHeaders, capabilityTransportPath}
	}
	if agentKind == "claude" && route.Auth.Type == domain.AuthAnthropicKey {
		return []string{capabilityTransportAnthropicAPIKey}
	}
	return []string{capabilityTransportHeaders}
}

func (s *Server) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeID, ok := routeIDFromPath(r.URL.Path)
		if !ok || s.registry == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "UNKNOWN_ROUTE"})
			return
		}
		select {
		case s.proxySlots <- struct{}{}:
			defer func() { <-s.proxySlots }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "CONCURRENCY_LIMIT"})
			return
		}
		var selected *domain.ProtectedRoute
		var selectedAgentID string
		var selectedAgentKind string
		var selectedWorkspace string
		for _, entry := range s.registry.List() {
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
		handler, err := veilproxy.NewHandlerWithScanner(s.manager, []veilproxy.Route{{ID: selected.ID, AgentID: selectedAgentID, SurfaceID: selected.SurfaceID, Workspace: workspaceRef, WorkspaceRef: workspaceRef, Protocol: selected.Protocol, Upstream: upstream, Auth: selected.Auth, AuthApplier: authApplier, Network: selected.Network, Auditor: s.auditor, CapabilityHeader: capabilityHeader, CapabilityPath: slices.Contains(capabilityTransports, capabilityTransportPath), Policy: s.policyEngine(), Interactive: true, Approver: s.broker, MaxRequestBytes: 8 << 20, MaxResponseBytes: 32 << 20, VaultLimits: redactor.Limits{MaxEntries: 4096, MaxOriginalBytes: 8 << 20}}}, &http.Client{Timeout: 5 * time.Minute}, s.currentScanner())
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

func decodeManagement(r *http.Request, destination any) error {
	return decodeManagementWithLimit(r, destination, maxManagementBody)
}

func decodeManagementWithLimit(r *http.Request, destination any, limit int64) error {
	if r == nil || r.Body == nil || destination == nil || limit <= 0 {
		return errors.New("management request, destination, and positive size limit are required")
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !protocol.MediaTypeIs(contentTypes[0], "application/json") {
		return errors.New("management request requires one valid application/json content type")
	}
	encodings := r.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return errors.New("management request content encoding is unsupported or ambiguous")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("management request too large")
	}
	if err := jsonsafe.Validate(body); err != nil {
		return errors.New("management request contains invalid or ambiguous JSON")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("management request contains trailing data")
	}
	return nil
}

func decodeModelUpload(r *http.Request) (modelstore.Manifest, error) {
	if r == nil || r.Body == nil {
		return modelstore.Manifest{}, errors.New("model upload is required")
	}
	contentTypes := r.Header.Values("Content-Type")
	encodings := r.Header.Values("Content-Encoding")
	encodedManifests := r.Header.Values(ModelManifestHeader)
	if len(contentTypes) != 1 || !protocol.MediaTypeIs(contentTypes[0], "application/octet-stream") || len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") || len(encodedManifests) != 1 || len(encodedManifests[0]) > maxModelManifestHeaderBytes {
		return modelstore.Manifest{}, errors.New("model upload representation is invalid or ambiguous")
	}
	payload, err := base64.StdEncoding.DecodeString(encodedManifests[0])
	if err != nil || base64.StdEncoding.EncodeToString(payload) != encodedManifests[0] || len(payload) > maxModelManifestHeaderBytes || jsonsafe.Validate(payload) != nil {
		return modelstore.Manifest{}, errors.New("model manifest header is invalid")
	}
	var manifest modelstore.Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return modelstore.Manifest{}, errors.New("model manifest header is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return modelstore.Manifest{}, errors.New("model manifest header contains trailing data")
	}
	if manifest.Size <= 0 || manifest.Size > modelstore.MaxArtifactBytes || r.ContentLength != manifest.Size {
		return modelstore.Manifest{}, errors.New("model upload length does not match manifest")
	}
	return manifest, nil
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if !s.manager.Delete(r.PathValue("id")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "NOT_FOUND"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	secureCoreResponseHeaders(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func secureCoreResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func ListenAddress(endpoint string) (string, error) {
	u := strings.TrimPrefix(endpoint, "http://")
	host, _, err := net.SplitHostPort(u)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return "", fmt.Errorf("core endpoint is not loopback: %s", endpoint)
	}
	return u, nil
}
