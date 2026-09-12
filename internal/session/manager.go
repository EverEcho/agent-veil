package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type RouteCredential struct {
	RouteID string `json:"route_id"`
	Token   string `json:"token"`
}

type Created struct {
	Session domain.ProtectionSession `json:"session"`
	Routes  []RouteCredential        `json:"routes"`
}

type managedSession struct {
	session domain.ProtectionSession
	routes  []RouteCredential
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*managedSession
	now      func() time.Time
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*managedSession), now: time.Now}
}

func (m *Manager) Create(parentID, endpoint string, routeIDs []string, ttl time.Duration) (Created, error) {
	if ttl <= 0 || len(routeIDs) == 0 {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "positive ttl and at least one route are required")
	}
	id, err := randomHex(16)
	if err != nil {
		return Created{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "secure randomness is unavailable")
	}
	routes := make([]RouteCredential, 0, len(routeIDs))
	seen := make(map[string]struct{}, len(routeIDs))
	for _, routeID := range routeIDs {
		if routeID == "" {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "route id cannot be empty")
		}
		if _, ok := seen[routeID]; ok {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "duplicate route id")
		}
		seen[routeID] = struct{}{}
		token, err := randomHex(32)
		if err != nil {
			return Created{}, err
		}
		routes = append(routes, RouteCredential{RouteID: routeID, Token: token})
	}
	now := m.now()
	s := domain.NewProtectionSession("session-"+id, parentID, endpoint, now, now.Add(ttl), routeIDs, secret)
	entry := &managedSession{session: s, routes: routes}
	m.mu.Lock()
	m.sessions[s.ID] = entry
	m.mu.Unlock()
	return Created{Session: s, Routes: append([]RouteCredential(nil), routes...)}, nil
}

func (m *Manager) List() []domain.ProtectionSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	result := make([]domain.ProtectionSession, 0, len(m.sessions))
	for id, entry := range m.sessions {
		if !entry.session.ExpiresAt.After(now) {
			wipe(entry)
			delete(m.sessions, id)
			continue
		}
		result = append(result, entry.session)
	}
	return result
}

func (m *Manager) Authorize(sessionID, routeID, token string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.sessions[sessionID]
	if !ok || !entry.session.ExpiresAt.After(m.now()) {
		return false
	}
	for _, route := range entry.routes {
		if route.RouteID == routeID && constantTimeStringEqual(route.Token, token) {
			return true
		}
	}
	return false
}

func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.sessions[id]
	if !ok {
		return false
	}
	wipe(entry)
	delete(m.sessions, id)
	return true
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, entry := range m.sessions {
		wipe(entry)
		delete(m.sessions, id)
	}
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", domain.NewError(domain.ErrInvalidContract, "generate capability", "secure randomness is unavailable")
	}
	return hex.EncodeToString(value), nil
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func wipe(entry *managedSession) {
	secret := entry.session.SessionSecret()
	for i := range secret {
		secret[i] = 0
	}
	for i := range entry.routes {
		entry.routes[i].Token = ""
	}
}
