package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	routes  []managedRouteCredential
	context context.Context
	cancel  context.CancelFunc
}

type managedRouteCredential struct {
	routeID string
	token   []byte
}

type Authorization struct {
	Secret      []byte
	ExpiresAt   time.Time
	Context     context.Context
	Interactive bool
}

type CreateOptions struct {
	Interactive bool
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*managedSession
	now      func() time.Time
	random   io.Reader
	limits   Limits
}

type Limits struct {
	MaxSessions int
	MaxRoutes   int
	MaxTTL      time.Duration
}

const (
	DefaultMaxSessions = 1024
	DefaultMaxRoutes   = 256
	DefaultMaxTTL      = 24 * time.Hour
	MaximumSessions    = 4096
	MaximumRoutes      = 256
	MaximumTTL         = 7 * 24 * time.Hour
	maxEndpointBytes   = 4096
)

var routeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func NewManager() *Manager {
	manager, _ := NewManagerWithLimits(Limits{MaxSessions: DefaultMaxSessions, MaxRoutes: DefaultMaxRoutes, MaxTTL: DefaultMaxTTL})
	return manager
}

func NewManagerWithLimits(limits Limits) (*Manager, error) {
	if limits.MaxSessions < 1 || limits.MaxSessions > MaximumSessions || limits.MaxRoutes < 1 || limits.MaxRoutes > MaximumRoutes || limits.MaxTTL <= 0 || limits.MaxTTL > MaximumTTL {
		return nil, domain.NewError(domain.ErrInvalidContract, "create session manager", "session, route, and TTL limits must be within configured bounds")
	}
	return &Manager{sessions: make(map[string]*managedSession), now: time.Now, random: rand.Reader, limits: limits}, nil
}

func (m *Manager) Create(parentID, endpoint string, routeIDs []string, ttl time.Duration) (Created, error) {
	return m.CreateWithOptions(parentID, endpoint, routeIDs, ttl, CreateOptions{})
}

func (m *Manager) CreateWithOptions(parentID, endpoint string, routeIDs []string, ttl time.Duration, options CreateOptions) (Created, error) {
	if ttl <= 0 || ttl > m.limits.MaxTTL || len(routeIDs) == 0 || len(routeIDs) > m.limits.MaxRoutes {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "ttl and route count must be within configured limits")
	}
	if endpoint == "" || len(endpoint) > maxEndpointBytes || !utf8.ValidString(endpoint) || strings.ContainsRune(endpoint, 0) {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "core endpoint is invalid")
	}
	seen := make(map[string]struct{}, len(routeIDs))
	for _, routeID := range routeIDs {
		if !routeIDPattern.MatchString(routeID) {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "route id is invalid")
		}
		if _, ok := seen[routeID]; ok {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "duplicate route id")
		}
		seen[routeID] = struct{}{}
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, entry := range m.sessions {
		if !entry.session.ExpiresAt.After(now) {
			m.deleteCascadeLocked(id)
		}
	}
	if len(m.sessions) >= m.limits.MaxSessions {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "active session capacity is exhausted")
	}
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
		if endpoint != parent.session.CoreEndpoint {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "child session must use its parent's Core endpoint")
		}
		parentRoutes := make(map[string]struct{}, len(parent.session.RouteIDs))
		for _, routeID := range parent.session.RouteIDs {
			parentRoutes[routeID] = struct{}{}
		}
		for _, routeID := range routeIDs {
			if _, ok := parentRoutes[routeID]; !ok {
				return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "child session cannot add routes outside its parent")
			}
		}
		if options.Interactive && !parent.session.Interactive {
			return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "child session cannot escalate interaction capability")
		}
	}
	id, err := m.randomHexString(16)
	if err != nil {
		return Created{}, err
	}
	if _, exists := m.sessions["session-"+id]; exists {
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "session capability collision")
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(m.random, secret); err != nil {
		wipeBytes(secret)
		return Created{}, domain.NewError(domain.ErrInvalidContract, "create session", "secure randomness is unavailable")
	}
	managedRoutes := make([]managedRouteCredential, 0, len(routeIDs))
	for _, routeID := range routeIDs {
		token, err := m.randomHexBytes(32)
		if err != nil {
			wipeBytes(secret)
			for i := range managedRoutes {
				wipeBytes(managedRoutes[i].token)
			}
			return Created{}, err
		}
		managedRoutes = append(managedRoutes, managedRouteCredential{routeID: routeID, token: token})
	}
	routes := make([]RouteCredential, len(managedRoutes))
	for index := range managedRoutes {
		routes[index] = RouteCredential{RouteID: managedRoutes[index].routeID, Token: string(managedRoutes[index].token)}
	}
	s := domain.NewProtectionSession("session-"+id, parentID, endpoint, now, now.Add(ttl), routeIDs, secret)
	s.Interactive = options.Interactive
	wipeBytes(secret)
	sessionContext, cancel := context.WithCancel(context.Background())
	entry := &managedSession{session: s, routes: managedRoutes, context: sessionContext, cancel: cancel}
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
		if route.routeID == routeID && constantTimeBytesStringEqual(route.token, token) {
			return Authorization{Secret: entry.session.SessionSecret(), ExpiresAt: entry.session.ExpiresAt, Context: entry.context, Interactive: entry.session.Interactive}, true
		}
	}
	return Authorization{}, false
}

// ContainsRoute validates management-plane ownership without exposing or
// comparing the route capability itself.
func (m *Manager) ContainsRoute(sessionID, routeID string) bool {
	if sessionID == "" || routeID == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.sessions[sessionID]
	if !ok {
		return false
	}
	if !entry.session.ExpiresAt.After(m.now()) {
		m.deleteCascadeLocked(sessionID)
		return false
	}
	for _, candidate := range entry.session.RouteIDs {
		if candidate == routeID {
			return true
		}
	}
	return false
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
	result := domain.NewProtectionSession(session.ID, session.ParentSessionID, session.CoreEndpoint, session.StartedAt, session.ExpiresAt, session.RouteIDs, nil)
	result.Interactive = session.Interactive
	return result
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

func (m *Manager) randomHexString(bytes int) (string, error) {
	value, err := m.randomHexBytes(bytes)
	if err != nil {
		return "", err
	}
	defer wipeBytes(value)
	return string(value), nil
}

func (m *Manager) randomHexBytes(bytes int) ([]byte, error) {
	raw := make([]byte, bytes)
	defer wipeBytes(raw)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "generate capability", "secure randomness is unavailable")
	}
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	return encoded, nil
}

func constantTimeBytesStringEqual(a []byte, b string) bool {
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
		wipeBytes(entry.routes[i].token)
		entry.routes[i].token = nil
	}
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
