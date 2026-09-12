package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/session"
)

const maxManagementBody = 64 << 10

type Server struct {
	manager    *session.Manager
	adminToken string
	listener   net.Listener
	httpServer *http.Server
}

func New(manager *session.Manager, adminToken string) (*Server, error) {
	if manager == nil || len(adminToken) < 32 {
		return nil, errors.New("manager and an admin token of at least 32 characters are required")
	}
	return &Server{manager: manager, adminToken: adminToken}, nil
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
	s.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = s.httpServer.Serve(listener) }()
	return nil
}

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
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxManagementBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.TTLSeconds <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_REQUEST"})
		return
	}
	created, err := s.manager.Create(request.ParentSessionID, s.Endpoint(), request.RouteIDs, time.Duration(request.TTLSeconds)*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_SESSION"})
		return
	}
	writeJSON(w, http.StatusCreated, created)
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
