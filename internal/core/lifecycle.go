package core

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/security"
)

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
	mux.HandleFunc("GET /v1/identity", s.identity)
	mux.HandleFunc("POST /v1/browser-sessions", s.auth(s.createBrowserSession))
	mux.HandleFunc("POST /v1/browser-sessions/exchange", s.exchangeBrowserSession)
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
	mux.HandleFunc("GET /v1/developer-settings", s.auth(s.getDeveloperSettings))
	mux.HandleFunc("PUT /v1/developer-settings", s.auth(s.updateDeveloperSettings))
	mux.HandleFunc("GET /v1/developer-traces", s.auth(s.listDeveloperTraces))
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
				if s.registry != nil {
					s.registry.List()
					s.applyRegistryRevocations()
				}
				s.manager.PruneExpired()
			case <-cleanupContext.Done():
				return
			}
		}
	}()
	go func() { _ = s.httpServer.Serve(listener) }()
	return nil
}

func (s *Server) Endpoint() string {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener == nil {
		return ""
	}
	return "http://" + s.listener.Addr().String()
}

func (s *Server) InstanceID() string { return s.instanceID }

func (s *Server) Close(ctx context.Context) error {
	s.lifecycleMu.Lock()
	cleanupCancel, cleanupDone, httpServer := s.cleanupCancel, s.cleanupDone, s.httpServer
	s.lifecycleMu.Unlock()
	s.manager.Close()
	s.legacySSE.CloseAll()
	if cleanupCancel != nil {
		cleanupCancel()
		<-cleanupDone
	}
	if httpServer == nil {
		return nil
	}
	return httpServer.Shutdown(ctx)
}
