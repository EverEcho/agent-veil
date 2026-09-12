package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

const maxManagementBody = 64 << 10

type Server struct {
	manager    *session.Manager
	adminToken string
	listener   net.Listener
	httpServer *http.Server
	registry   *registry.Registry
	broker     *policy.Broker
	policy     policy.Engine
	auditor    interface {
		Append(domain.AuditEvent) error
	}
	auditReader interface {
		Recent(time.Time) ([]domain.AuditEvent, error)
	}
}

func (s *Server) WithRegistry(value *registry.Registry) *Server { s.registry = value; return s }

func New(manager *session.Manager, adminToken string) (*Server, error) {
	if manager == nil || len(adminToken) < 32 {
		return nil, errors.New("manager and an admin token of at least 32 characters are required")
	}
	return &Server{manager: manager, adminToken: adminToken, broker: policy.NewBroker(), policy: policy.Engine{Default: domain.ActionRedact}}, nil
}

func (s *Server) WithPolicy(engine policy.Engine) *Server { s.policy = engine; return s }
func (s *Server) WithAuditor(value interface{ Append(domain.AuditEvent) error }) *Server {
	s.auditor = value
	if reader, ok := value.(interface {
		Recent(time.Time) ([]domain.AuditEvent, error)
	}); ok {
		s.auditReader = reader
	}
	return s
}

func (s *Server) Start() error {
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
	mux.HandleFunc("DELETE /v1/agents/{id}", s.auth(s.deleteAgent))
	mux.HandleFunc("GET /v1/approvals", s.auth(s.listApprovals))
	mux.HandleFunc("POST /v1/approvals/{id}", s.auth(s.resolveApproval))
	mux.HandleFunc("GET /v1/audit", s.auth(s.listAudit))
	mux.HandleFunc("GET /", s.dashboard)
	mux.Handle("POST /route/", s.proxyHandler())
	mux.Handle("GET /route/", s.proxyHandler())
	s.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, dashboardHTML)
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

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "REGISTRY_UNAVAILABLE"})
		return
	}
	s.registry.Remove(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

const dashboardHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentVeil</title><style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui;background:#0b0e14;color:#e8edf5}body{max-width:1100px;margin:0 auto;padding:40px 24px}h1{letter-spacing:-.04em}.muted{color:#8c98aa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}.card{background:#141925;border:1px solid #273044;border-radius:14px;padding:18px}.status{font-weight:700;text-transform:uppercase}.active,.protected,.local{color:#55d89b}.blocked,.unprotected{color:#ff6b76}.partial,.observed{color:#f2bd5a}button,input{background:#1e2635;color:inherit;border:1px solid #35415a;border-radius:8px;padding:10px}button{cursor:pointer}</style></head><body>
<h1>AgentVeil</h1><p class="muted">Local privacy control plane</p><div><input id="token" type="password" placeholder="Management token"><button id="load">Load status</button></div><p id="message" class="muted"></p><div id="approvals" class="grid"></div><div id="agents" class="grid"></div><h2>Recent decisions</h2><div id="audit" class="grid"></div>
<script>const e=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),token=()=>document.querySelector('#token').value;async function decide(id,action){await fetch('/v1/approvals/'+id,{method:'POST',headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'},body:JSON.stringify({action})});await load()}async function load(){const m=document.querySelector('#message');try{const headers={Authorization:'Bearer '+token()},[agents,approvals,audit]=await Promise.all([fetch('/v1/agents',{headers}),fetch('/v1/approvals',{headers}),fetch('/v1/audit',{headers})]);if(!agents.ok||!approvals.ok||!audit.ok)throw Error('unauthorized');const rows=await agents.json(),asks=await approvals.json(),events=await audit.json();m.textContent=rows.length+' agents discovered · '+events.length+' retained decisions';document.querySelector('#approvals').innerHTML=asks.map(x=>'<section class="card"><div class="status partial">Decision required</div><h2>'+e(x.finding.category)+'</h2><p>'+e(x.finding.severity)+' · '+e(x.finding.location.path)+'</p><button onclick="decide(\''+x.id+'\',\'redact\')">Redact once</button> <button onclick="decide(\''+x.id+'\',\'allow\')">Allow once</button> <button onclick="decide(\''+x.id+'\',\'block\')">Block</button></section>').join('');document.querySelector('#agents').innerHTML=rows.map(x=>'<section class="card"><div class="status '+e(x.state)+'">'+e(x.state)+'</div><h2>'+e(x.manifest.agent.kind)+'</h2><p class="muted">'+e(x.manifest.agent.version||'unknown version')+'</p><p>Protected '+x.plan.summary.protected+' · Local '+x.plan.summary.local+' · Partial '+x.plan.summary.partial+' · Observed '+x.plan.summary.observed+' · Unprotected '+x.plan.summary.unprotected+'</p></section>').join('');document.querySelector('#audit').innerHTML=events.slice(-20).reverse().map(x=>'<section class="card"><div class="status '+e(x.action)+'">'+e(x.action)+'</div><p>'+e(x.agent_id||'unknown')+' · '+e(x.surface_id||'unknown')+'</p><p class="muted">'+e(x.protocol||'unknown')+' · '+Number(x.finding_count||0)+' findings · '+Number(x.latency_ms||0)+' ms'+(x.error_code?' · '+e(x.error_code):'')+'</p></section>').join('')}catch(err){m.textContent='Unable to load protected status';document.querySelector('#agents').textContent='';document.querySelector('#audit').textContent=''}}document.querySelector('#load').onclick=load;setInterval(()=>{if(token())load()},1000)</script></body></html>`

func (s *Server) Endpoint() string {
	if s.listener == nil {
		return ""
	}
	return "http://" + s.listener.Addr().String()
}

func (s *Server) Close(ctx context.Context) error {
	s.manager.Close()
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !secureEqual(provided, s.adminToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "UNAUTHORIZED_MANAGEMENT_API"})
			return
		}
		next(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "api_version": "v1"})
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
	if err := decodeManagement(r, &request); err != nil || request.TTLSeconds <= 0 {
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
		var selected *domain.ProtectedRoute
		var selectedAgentID string
		for _, entry := range s.registry.List() {
			if entry.State != registry.StateActive {
				continue
			}
			for i := range entry.Plan.Routes {
				route := entry.Plan.Routes[i]
				if route.ID == routeID {
					selected = &route
					selectedAgentID = entry.Manifest.Agent.ID
					break
				}
			}
		}
		if selected == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "UNKNOWN_ROUTE"})
			return
		}
		upstream, err := url.Parse(selected.Upstream.Scheme + "://" + selected.Upstream.Host + ":" + strconv.Itoa(int(selected.Upstream.Port)))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "INVALID_ROUTE"})
			return
		}
		authApplier, err := veilauth.NewRuntimeApplier(selected.Auth, upstream)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "INVALID_ROUTE"})
			return
		}
		handler, err := veilproxy.NewHandler(s.manager, []veilproxy.Route{{ID: selected.ID, AgentID: selectedAgentID, SurfaceID: selected.SurfaceID, Protocol: selected.Protocol, Upstream: upstream, Auth: selected.Auth, AuthApplier: authApplier, Network: selected.Network, Auditor: s.auditor, Policy: s.policy, Interactive: true, Approver: s.broker, MaxRequestBytes: 8 << 20, MaxResponseBytes: 32 << 20, VaultLimits: redactor.Limits{MaxEntries: 4096, MaxOriginalBytes: 8 << 20}}}, &http.Client{Timeout: 5 * time.Minute})
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
	body, err := io.ReadAll(io.LimitReader(r.Body, maxManagementBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxManagementBody {
		return errors.New("management request too large")
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

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if !s.manager.Delete(r.PathValue("id")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "NOT_FOUND"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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
