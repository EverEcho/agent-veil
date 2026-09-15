package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentveil/agentveil/internal/debugtrace"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
	"github.com/agentveil/agentveil/internal/feedback"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/policy"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
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
	instanceID       string
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
	feedbackStore   *feedback.Store
	debugTraceStore *debugtrace.Store
	proxySlots      chan struct{}
	streamSlots     chan struct{}
	legacySSE       *veilproxy.LegacySSEManager
	discoverer      interface {
		DetectAll(context.Context) []discovery.Detection
	}
	scanner       detector.ContentScanner
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
	browserAuth   *browserSessionStore
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
	instanceBytes := make([]byte, 32)
	if _, err := rand.Read(instanceBytes); err != nil {
		return nil, fmt.Errorf("generate Core instance identity: %w", err)
	}
	return &Server{manager: manager, adminToken: adminToken, instanceID: base64.RawStdEncoding.EncodeToString(instanceBytes), broker: policy.NewBroker(), policy: policy.Engine{Default: domain.ActionRedact}, proxySlots: make(chan struct{}, defaultMaxConcurrentProxyRequests), streamSlots: make(chan struct{}, defaultMaxConcurrentProxyRequests), legacySSE: veilproxy.NewDefaultLegacySSEManager(), discoverer: discovery.Default(), scanner: scanner, browserAuth: newBrowserSessionStore()}, nil
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
	s.streamSlots = make(chan struct{}, limit)
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

func (s *Server) WithDebugTraceStore(store *debugtrace.Store) error {
	if store == nil {
		return domain.NewError(domain.ErrInvalidContract, "configure developer traces", "developer trace store is required")
	}
	s.debugTraceStore = store
	return nil
}

type unexpectedEgressReport struct {
	SessionID  string           `json:"session_id"`
	AgentID    string           `json:"agent_id"`
	Generation uint64           `json:"generation"`
	RouteID    string           `json:"route_id"`
	Transport  egress.Transport `json:"transport"`
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

type rulePackInventory struct {
	Active   string               `json:"active,omitempty"`
	Versions []rulestore.Manifest `json:"versions"`
}

type rulePackInstall struct {
	Manifest       rulestore.Manifest `json:"manifest"`
	ArtifactBase64 string             `json:"artifact_base64"`
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

type createRequest struct {
	ParentSessionID string   `json:"parent_session_id"`
	RouteIDs        []string `json:"route_ids"`
	TTLSeconds      int64    `json:"ttl_seconds"`
	Interactive     bool     `json:"interactive"`
}
