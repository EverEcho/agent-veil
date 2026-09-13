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

type Server struct {
	lifecycleMu sync.Mutex
	manager     *session.Manager
	adminToken  string
	listener    net.Listener
	httpServer  *http.Server
	registry    *registry.Registry
	broker      *policy.Broker
	policy      policy.Engine
	policyMu    sync.RWMutex
	policyStore *policy.Store
	ruleStore   *rulestore.Store
	modelStore  *modelstore.Store
	scannerMu   sync.RWMutex
	auditor     interface {
		Append(domain.AuditEvent) error
	}
	auditMonitor *monitoredAuditor
	auditReader  interface {
		Recent(time.Time) ([]domain.AuditEvent, error)
	}
	proxySlots chan struct{}
	discoverer interface {
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
	pack, _, err := store.OpenActive()
	if errors.Is(err, os.ErrNotExist) {
		s.ruleStore = store
		return nil
	}
	if err != nil {
		return err
	}
	base, err := detector.NewDefaultWithRulePack(pack)
	if err != nil {
		return err
	}
	scanner, err := detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
	if err != nil {
		return err
	}
	s.ruleStore = store
	s.scannerMu.Lock()
	s.scanner = scanner
	s.scannerMu.Unlock()
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

func (s *Server) testDetection(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Text string `json:"text"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Text == "" || len(request.Text) > 32<<10 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_DETECTION_TEST"})
		return
	}
	matches, err := s.currentScanner().ScanChecked("/test-input", request.Text)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "DETECTOR_FAILURE"})
		return
	}
	findings := make([]domain.Finding, len(matches))
	for index := range matches {
		findings[index] = matches[index].Finding
	}
	writeJSON(w, http.StatusOK, findings)
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
	base := detector.NewDefault()
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
}

func (s *Server) listModels(w http.ResponseWriter, _ *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
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
	} else if !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_MODEL_INVALID"})
		return
	}
	writeJSON(w, http.StatusOK, inventory)
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
	if err := s.modelStore.Activate(request.Version); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deactivateModel(w http.ResponseWriter, _ *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	if err := s.modelStore.Deactivate(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_DEACTIVATION_FAILED"})
		return
	}
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
			owners[route.ID] = registry.CallSurface{RouteID: route.ID, AgentID: entry.Manifest.Agent.ID, SurfaceID: route.SurfaceID, Coverage: domain.CoverageProtected}
		}
	}
	nodes := make([]registry.CallNode, 0)
	for _, activeSession := range s.manager.List() {
		node := registry.CallNode{SessionID: activeSession.ID, ParentSessionID: activeSession.ParentSessionID}
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

const dashboardHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentVeil</title><style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui;background:#0b0e14;color:#e8edf5}body{max-width:1100px;margin:0 auto;padding:40px 24px}h1{letter-spacing:-.04em}.muted{color:#8c98aa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}.card{background:#141925;border:1px solid #273044;border-radius:14px;padding:18px}.call{margin:8px 0}.depth-0{margin-left:0}.depth-1{margin-left:24px}.depth-2{margin-left:48px}.depth-3{margin-left:72px}.depth-4{margin-left:96px}.depth-5{margin-left:120px}.depth-6{margin-left:144px}.depth-7{margin-left:168px}.depth-8{margin-left:192px}.status{font-weight:700;text-transform:uppercase}.active,.protected,.local{color:#55d89b}.blocked,.unprotected,.error{color:#ff6b76}.partial,.observed{color:#f2bd5a}button,input,textarea{background:#1e2635;color:inherit;border:1px solid #35415a;border-radius:8px;padding:10px}button{cursor:pointer}textarea{box-sizing:border-box;width:100%;min-height:150px;font:13px ui-monospace,monospace;resize:vertical}.controls{display:flex;gap:10px;align-items:center;margin-top:10px}</style></head><body>
<h1>AgentVeil</h1><p class="muted">Local privacy control plane</p><div><input id="token" type="password" placeholder="Management token"><button id="load">Load status</button></div><p id="message" class="muted"></p><div id="approvals" class="grid"></div><h2>Installed agents</h2><div id="discovered" class="grid"></div><h2>Inspection preview</h2><div id="inspection"><p class="muted">Select an installed agent to inspect its surfaces without taking control.</p></div><h2>Registered protection</h2><div id="agents" class="grid"></div><h2>Active call tree</h2><div id="calls"></div><h2>Policy</h2><section class="card"><textarea id="policy" spellcheck="false" aria-label="Policy JSON"></textarea><div class="controls"><button id="save-policy">Validate and save</button><span id="policy-result" class="muted"></span></div></section><h2>Rule packs</h2><div id="rule-packs"><p class="muted">Load status to inspect verified rule packs.</p></div><section class="card"><textarea id="rule-manifest" spellcheck="false" aria-label="Signed rule manifest JSON" placeholder="Paste the signed rule manifest JSON"></textarea><div class="controls"><input id="rule-artifact" type="file" accept="application/json,.json" aria-label="Rule pack JSON file"><button id="install-rule">Verify and install</button><span id="rule-install-result" class="muted"></span></div></section><h2>Semantic models</h2><div id="models"><p class="muted">Load status to inspect verified semantic models.</p></div><section class="card"><textarea id="model-manifest" spellcheck="false" aria-label="Signed model manifest JSON" placeholder="Paste the signed model manifest JSON"></textarea><div class="controls"><input id="model-artifact" type="file" accept=".onnx,application/octet-stream" aria-label="ONNX model file"><button id="install-model">Verify and install model</button><span id="model-install-result" class="muted"></span></div></section><h2>Rule test</h2><section class="card"><textarea id="test-input" spellcheck="false" autocomplete="off" aria-label="Sensitive test input" placeholder="Test input is processed locally and cleared after scanning"></textarea><div class="controls"><button id="test-rules">Scan locally</button><span id="test-result" class="muted"></span></div><div id="test-findings"></div></section><h2>Recent decisions</h2><div id="audit" class="grid"></div>
<script>
const e=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),token=()=>document.querySelector('#token').value;
async function decide(id,action){await fetch('/v1/approvals/'+id,{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({action})});await load()}
function renderCalls(tree,parent,depth){return(tree[parent]||[]).map(node=>'<div class="card call depth-'+Math.min(depth,8)+'"><div class="muted">Session '+e(node.session_id)+'</div>'+node.surfaces.map(surface=>'<div><span class="status '+e(surface.coverage)+'">'+e(surface.coverage)+'</span> · '+e(surface.agent_id||'unregistered')+' / '+e(surface.surface_id||surface.route_id)+'</div>').join('')+'</div>'+renderCalls(tree,node.session_id,depth+1)).join('')}
async function loadPolicy(){const response=await fetch('/v1/policy',{headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('policy unavailable');if(document.activeElement!==document.querySelector('#policy'))document.querySelector('#policy').value=JSON.stringify(await response.json(),null,2)}
async function savePolicy(){const result=document.querySelector('#policy-result');try{const documentValue=JSON.parse(document.querySelector('#policy').value),response=await fetch('/v1/policy',{method:'PUT',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify(documentValue)});if(!response.ok)throw Error('invalid policy');result.className='active';result.textContent='Policy saved atomically'}catch(err){result.className='error';result.textContent='Policy rejected; check JSON, actions, and scoped identifiers'}}
async function loadRulePacks(){const output=document.querySelector('#rule-packs'),response=await fetch('/v1/rules',{headers:{Authorization:'Bearer '+token()}});if(response.status===503){output.innerHTML='<p class="muted">Signed rule storage is not configured.</p>';return}if(!response.ok)throw Error('rule inventory unavailable');const inventory=await response.json(),active=inventory.active||'';output.innerHTML='<section class="card"><p><span class="status '+(active?'active':'local')+'">'+(active?'verified '+e(active):'built-in')+'</span></p><div class="controls"><button id="use-built-in" '+(active?'':'disabled')+'>Use built-in rules</button></div>'+inventory.versions.map(version=>'<p>'+e(version.version)+' · '+Number(version.size)+' bytes '+(version.version===active?'<span class="status active">active</span>':'<button class="activate-rule" data-version="'+e(version.version)+'">Activate</button> <button class="remove-rule" data-version="'+e(version.version)+'">Remove</button>')+'</p>').join('')+'</section>'}
async function activateRulePack(version){const response=await fetch('/v1/rules/active',{method:'PUT',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({version})});if(!response.ok)throw Error('activation failed');await loadRulePacks()}
async function deactivateRulePack(){const response=await fetch('/v1/rules/active',{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('deactivation failed');await loadRulePacks()}
async function removeRulePack(version){if(!window.confirm('Remove inactive rule pack '+version+'?'))return;const response=await fetch('/v1/rules/'+encodeURIComponent(version),{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('removal failed');await loadRulePacks()}
function encodeBase64(bytes){let binary='';for(let offset=0;offset<bytes.length;offset+=32768)binary+=String.fromCharCode(...bytes.subarray(offset,offset+32768));return btoa(binary)}
async function installRulePack(){const result=document.querySelector('#rule-install-result'),manifestInput=document.querySelector('#rule-manifest'),fileInput=document.querySelector('#rule-artifact');try{const file=fileInput.files[0];if(!file||file.size<1||file.size>1048576)throw Error('invalid artifact size');const manifest=JSON.parse(manifestInput.value),artifact_base64=encodeBase64(new Uint8Array(await file.arrayBuffer())),response=await fetch('/v1/rules',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({manifest,artifact_base64})});fileInput.value='';if(!response.ok)throw Error('installation failed');manifestInput.value='';result.className='active';result.textContent='Signed rule pack installed but not activated';await loadRulePacks()}catch(err){fileInput.value='';result.className='error';result.textContent='Installation rejected; verify manifest, signature, and file size'}}
async function loadModels(){const output=document.querySelector('#models'),response=await fetch('/v1/models',{headers:{Authorization:'Bearer '+token()}});if(response.status===503){output.innerHTML='<p class="muted">Signed semantic-model storage is not configured.</p>';return}if(!response.ok)throw Error('model inventory unavailable');const inventory=await response.json(),active=inventory.active||'';output.innerHTML='<section class="card"><p><span class="status '+(active?'active':'observed')+'">'+(active?'selected '+e(active):'no model selected')+'</span></p><p class="muted">A selected artifact is verified storage state; semantic inference remains unavailable until the local runtime is connected.</p><div class="controls"><button id="deactivate-model" '+(active?'':'disabled')+'>Deactivate model</button></div>'+inventory.versions.map(version=>'<p>'+e(version.version)+' · '+Number(version.size)+' bytes '+(version.version===active?'<span class="status active">selected</span>':'<button class="activate-model" data-version="'+e(version.version)+'">Select</button> <button class="remove-model" data-version="'+e(version.version)+'">Remove</button>')+'</p>').join('')+'</section>'}
async function activateModel(version){const response=await fetch('/v1/models/active',{method:'PUT',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({version})});if(!response.ok)throw Error('model selection failed');await loadModels()}
async function deactivateModel(){const response=await fetch('/v1/models/active',{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('model deactivation failed');await loadModels()}
async function removeModel(version){if(!window.confirm('Remove inactive semantic model '+version+'?'))return;const response=await fetch('/v1/models/'+encodeURIComponent(version),{method:'DELETE',headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('model removal failed');await loadModels()}
async function installModel(){const result=document.querySelector('#model-install-result'),manifestInput=document.querySelector('#model-manifest'),fileInput=document.querySelector('#model-artifact');try{const file=fileInput.files[0],manifest=JSON.parse(manifestInput.value);if(!file||file.size<1||file.size>536870912||Number(manifest.size)!==file.size)throw Error('invalid artifact size');const encodedManifest=encodeBase64(new TextEncoder().encode(JSON.stringify(manifest))),response=await fetch('/v1/models',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/octet-stream','X-AgentVeil-Model-Manifest':encodedManifest},body:file});fileInput.value='';if(!response.ok)throw Error('model installation failed');manifestInput.value='';result.className='active';result.textContent='Signed model installed but not selected';await loadModels()}catch(err){fileInput.value='';result.className='error';result.textContent='Installation rejected; verify manifest, signature, digest, and file size'}}
async function testRules(){const input=document.querySelector('#test-input'),result=document.querySelector('#test-result'),output=document.querySelector('#test-findings');try{const response=await fetch('/v1/detect',{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({text:input.value})});input.value='';if(!response.ok)throw Error('scan failed');const findings=await response.json();result.className='active';result.textContent=findings.length+' findings; input cleared';output.innerHTML=findings.map(finding=>'<p><span class="status '+e(finding.severity)+'">'+e(finding.severity)+'</span> · '+e(finding.category)+' · bytes '+Number(finding.location.start)+'–'+Number(finding.location.end)+'</p>').join('')||'<p class="muted">No deterministic findings</p>'}catch(err){input.value='';output.textContent='';result.className='error';result.textContent='Scan rejected; input cleared'}}
async function inspectAgent(name){const output=document.querySelector('#inspection');try{const response=await fetch('/v1/discovery/'+encodeURIComponent(name),{headers:{Authorization:'Bearer '+token()}});if(!response.ok)throw Error('inspection failed');const x=await response.json(),coverage=Object.fromEntries(x.protection_plan.coverage.map(item=>[item.surface_id,item]));output.innerHTML='<section class="card"><h2>'+e(x.manifest.agent.kind)+' <span class="muted">'+e(x.manifest.agent.version)+'</span></h2><p>Protected '+x.protection_plan.summary.protected+' · Local '+x.protection_plan.summary.local+' · Partial '+x.protection_plan.summary.partial+' · Observed '+x.protection_plan.summary.observed+' · Unprotected '+x.protection_plan.summary.unprotected+'</p>'+x.manifest.surfaces.map(surface=>{const status=coverage[surface.id]||{status:'unprotected',reason:'No coverage result'};return '<p><span class="status '+e(status.status)+'">'+e(status.status)+'</span> · '+e(surface.name)+' · '+e(surface.protocol)+'<br><span class="muted">'+e(status.reason)+'</span></p>'}).join('')+'</section>'}catch(err){output.innerHTML='<p class="error">Inspection unavailable; no control changes were made.</p>'}}
async function load(){const m=document.querySelector('#message');try{const headers={Authorization:'Bearer '+token()},responses=await Promise.all([fetch('/v1/agents',{headers}),fetch('/v1/approvals',{headers}),fetch('/v1/audit',{headers}),fetch('/v1/call-tree',{headers}),fetch('/v1/discovery',{headers})]);if(responses.some(response=>!response.ok))throw Error('unauthorized');const rows=await responses[0].json(),asks=await responses[1].json(),events=await responses[2].json(),calls=await responses[3].json(),detections=await responses[4].json(),sessionCount=Object.values(calls).reduce((total,nodes)=>total+nodes.length,0);m.textContent=detections.length+' installed · '+rows.length+' registered · '+sessionCount+' active sessions · '+events.length+' retained decisions';document.querySelector('#approvals').innerHTML=asks.map(x=>'<section class="card"><div class="status partial">Decision required</div><h2>'+e(x.finding.category)+'</h2><p>'+e(x.finding.severity)+' · '+e(x.finding.location.path)+'</p><button class="approval-decision" data-id="'+e(x.id)+'" data-action="redact">Redact once</button> <button class="approval-decision" data-id="'+e(x.id)+'" data-action="allow">Allow once</button> <button class="approval-decision" data-id="'+e(x.id)+'" data-action="block">Block</button></section>').join('');document.querySelector('#discovered').innerHTML=detections.map(x=>'<section class="card"><div class="status '+e(x.status==='verified'?'active':'observed')+'">'+e(x.status)+'</div><h2>'+e(x.agent)+'</h2><p class="muted">'+e(x.version||'unknown version')+'</p><button class="inspect-agent" data-agent="'+e(x.agent)+'">Inspect surfaces</button></section>').join('')||'<p class="muted">No supported agents found</p>';document.querySelector('#agents').innerHTML=rows.map(x=>'<section class="card"><div class="status '+e(x.state)+'">'+e(x.state)+'</div><h2>'+e(x.manifest.agent.kind)+'</h2><p class="muted">'+e(x.manifest.agent.version||'unknown version')+'</p><p>Protected '+x.plan.summary.protected+' · Local '+x.plan.summary.local+' · Partial '+x.plan.summary.partial+' · Observed '+x.plan.summary.observed+' · Unprotected '+x.plan.summary.unprotected+'</p></section>').join('');document.querySelector('#calls').innerHTML=renderCalls(calls,'',0)||'<p class="muted">No active sessions</p>';document.querySelector('#audit').innerHTML=events.slice(-20).reverse().map(x=>'<section class="card"><div class="status '+e(x.action)+'">'+e(x.action)+'</div><p>'+e(x.agent_id||'unknown')+' · '+e(x.surface_id||'unknown')+'</p><p class="muted">'+e(x.protocol||'unknown')+' · '+Number(x.finding_count||0)+' findings · '+Number(x.latency_ms||0)+' ms'+(x.error_code?' · '+e(x.error_code):'')+'</p></section>').join('')}catch(err){m.textContent='Unable to load protected status';for(const id of ['discovered','agents','calls','audit'])document.querySelector('#'+id).textContent=''}}
document.querySelector('#load').onclick=()=>{load();loadPolicy().catch(()=>{document.querySelector('#policy-result').textContent='Unable to load policy'});loadRulePacks().catch(()=>{document.querySelector('#rule-packs').innerHTML='<p class="error">Rule inventory unavailable.</p>'});loadModels().catch(()=>{document.querySelector('#models').innerHTML='<p class="error">Model inventory unavailable.</p>'})};document.querySelector('#save-policy').onclick=savePolicy;document.querySelector('#install-rule').onclick=installRulePack;document.querySelector('#install-model').onclick=installModel;document.querySelector('#test-rules').onclick=testRules;setInterval(()=>{if(token())load()},1000)
document.querySelector('#discovered').onclick=event=>{const button=event.target.closest('.inspect-agent');if(button)inspectAgent(button.dataset.agent)}
document.querySelector('#approvals').onclick=event=>{const button=event.target.closest('.approval-decision');if(button)decide(button.dataset.id,button.dataset.action)}
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
		w.Header().Set(APIVersionHeader, APIVersion)
		requestedVersions := r.Header.Values(APIVersionHeader)
		if len(requestedVersions) > 1 || len(requestedVersions) == 1 && requestedVersions[0] != APIVersion {
			writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "INCOMPATIBLE_MANAGEMENT_API"})
			return
		}
		if !security.ValidLocalOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": string(domain.ErrInvalidOrigin)})
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

func (s *Server) listSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.manager.List())
}

type createRequest struct {
	ParentSessionID string   `json:"parent_session_id"`
	RouteIDs        []string `json:"route_ids"`
	TTLSeconds      int64    `json:"ttl_seconds"`
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
	created, err := s.manager.Create(request.ParentSessionID, s.Endpoint(), request.RouteIDs, time.Duration(request.TTLSeconds)*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_SESSION"})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) routeExists(routeID string) bool {
	if s.registry == nil {
		return false
	}
	for _, entry := range s.registry.List() {
		if entry.State != registry.StateActive {
			continue
		}
		for _, route := range entry.Plan.Routes {
			if route.ID == routeID {
				return true
			}
		}
	}
	return false
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
		if selectedAgentKind == "claude" && selected.Auth.Type == domain.AuthAnthropicKey {
			capabilityHeader = "X-Api-Key"
		}
		handler, err := veilproxy.NewHandlerWithScanner(s.manager, []veilproxy.Route{{ID: selected.ID, AgentID: selectedAgentID, SurfaceID: selected.SurfaceID, Workspace: workspaceRef, WorkspaceRef: workspaceRef, Protocol: selected.Protocol, Upstream: upstream, Auth: selected.Auth, AuthApplier: authApplier, Network: selected.Network, Auditor: s.auditor, CapabilityHeader: capabilityHeader, Policy: s.policyEngine(), Interactive: true, Approver: s.broker, MaxRequestBytes: 8 << 20, MaxResponseBytes: 32 << 20, VaultLimits: redactor.Limits{MaxEntries: 4096, MaxOriginalBytes: 8 << 20}}}, &http.Client{Timeout: 5 * time.Minute}, s.currentScanner())
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
