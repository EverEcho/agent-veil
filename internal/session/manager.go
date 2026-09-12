package session

import (
	"context"
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
	context context.Context
	cancel  context.CancelFunc
}

type Authorization struct {
	Secret    []byte
	ExpiresAt time.Time
	Context   context.Context
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
	seen := make(map[string]struct{}, len(routeIDs))
	for _, routeID := range routeIDs {
		if routeID == "" {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "route id cannot be empty")
		}
		if _, ok := seen[routeID]; ok {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "duplicate route id")
		}
		seen[routeID] = struct{}{}
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if parentID != "" {
		parent, ok := m.sessions[parentID]
		if !ok || !parent.session.ExpiresAt.After(now) {
			if ok {
				m.deleteCascadeLocked(parentID)
			}
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "parent session is missing or expired")
		}
		if now.Add(ttl).After(parent.session.ExpiresAt) {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "child session cannot outlive its parent")
		}
	}
	id, err := randomHex(16)
	if err != nil {
		return Created{}, err
	}
	if _, exists := m.sessions["session-"+id]; exists {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "session capability collision")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "secure randomness is unavailable")
	}
	routes := make([]RouteCredential, 0, len(routeIDs))
	for _, routeID := range routeIDs {
		token, err := randomHex(32)
		if err != nil {
			for i := range secret {
				secret[i] = 0
			}
			return Created{}, err
		}
		routes = append(routes, RouteCredential{RouteID: routeID, Token: token})
	}
	s := domain.NewProtectionSession("session-"+id, parentID, endpoint, now, now.Add(ttl), routeIDs, secret)
	sessionContext, cancel := context.WithCancel(context.Background())
	entry := &managedSession{session: s, routes: routes, context: sessionContext, cancel: cancel}
	m.sessions[s.ID] = entry
	return Created{Session: publicSession(s), Routes: append([]RouteCredential(nil), routes...)}, nil
}

func (m *Manager) List() []domain.ProtectionSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	result := make([]domain.ProtectionSession, 0, len(m.sessions))
	for id, entry := range m.sessions {
		if !entry.session.ExpiresAt.After(now) {
			m.deleteCascadeLocked(id)
			continue
		}
		result = append(result, publicSession(entry.session))
	}
	return result
}

func (m *Manager) Authorize(sessionID, routeID, token string) bool {
	_, ok := m.AuthorizeAndSecret(sessionID, routeID, token)
	return ok
}

func (m *Manager) AuthorizeAndSecret(sessionID, routeID, token string) ([]byte, bool) {
	authorization, ok := m.AuthorizeRoute(sessionID, routeID, token)
	return authorization.Secret, ok
}

func (m *Manager) AuthorizeRoute(sessionID, routeID, token string) (Authorization, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.sessions[sessionID]
	if !ok {
		return Authorization{}, false
	}
	if !entry.session.ExpiresAt.After(m.now()) {
		m.deleteCascadeLocked(sessionID)
		return Authorization{}, false
	}
	for _, route := range entry.routes {
		if route.RouteID == routeID && constantTimeStringEqual(route.Token, token) {
			return Authorization{Secret: entry.session.SessionSecret(), ExpiresAt: entry.session.ExpiresAt, Context: entry.context}, true
		}
	}
	return Authorization{}, false
}

func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.sessions[id]
	if !ok {
		return false
	}
	m.deleteCascadeLocked(id)
	return true
}

func (m *Manager) PruneExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	before := len(m.sessions)
	now := m.now()
	for id, entry := range m.sessions {
		if !entry.session.ExpiresAt.After(now) {
			m.deleteCascadeLocked(id)
		}
	}
	return before - len(m.sessions)
}

func (m *Manager) deleteCascadeLocked(rootID string) {
	pending := map[string]struct{}{rootID: {}}
	for changed := true; changed; {
		changed = false
		for id, entry := range m.sessions {
			if _, selected := pending[id]; selected {
				continue
			}
			if _, parentSelected := pending[entry.session.ParentSessionID]; parentSelected {
				pending[id] = struct{}{}
				changed = true
			}
		}
	}
	for id := range pending {
		if entry, ok := m.sessions[id]; ok {
			entry.cancel()
			wipe(entry)
			delete(m.sessions, id)
		}
	}
}

func publicSession(session domain.ProtectionSession) domain.ProtectionSession {
	return domain.NewProtectionSession(session.ID, session.ParentSessionID, session.CoreEndpoint, session.StartedAt, session.ExpiresAt, session.RouteIDs, nil)
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, entry := range m.sessions {
		entry.cancel()
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
	entry.session.DestroySecret()
	for i := range entry.routes {
		entry.routes[i].Token = ""
	}
}
