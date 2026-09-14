package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/security"
)

const browserSessionCookie = "agentveil_browser_session"
const browserTicketTTL = 30 * time.Second
const browserSessionTTL = 8 * time.Hour
const maxBrowserTickets = 32
const maxBrowserSessions = 32

type browserSessionStore struct {
	mu       sync.Mutex
	tickets  map[[sha256.Size]byte]time.Time
	sessions map[[sha256.Size]byte]time.Time
}

func newBrowserSessionStore() *browserSessionStore {
	return &browserSessionStore{tickets: make(map[[sha256.Size]byte]time.Time), sessions: make(map[[sha256.Size]byte]time.Time)}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validVersionedLocalRequest(w, r) {
			return
		}
		provided, ok := managementBearer(r.Header.Values("Authorization"))
		if len(r.Header.Values("Authorization")) == 0 {
			ok = s.browserAuth.validSession(r)
		} else {
			ok = ok && secureEqual(provided, s.adminToken)
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "UNAUTHORIZED_MANAGEMENT_API"})
			return
		}
		next(w, r)
	}
}

func (s *Server) createBrowserSession(w http.ResponseWriter, _ *http.Request) {
	ticket, expiresAt, err := s.browserAuth.mintTicket(time.Now())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "BROWSER_SESSION_CAPACITY_EXHAUSTED"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ticket": ticket, "expires_at": expiresAt.UTC().Format(time.RFC3339)})
}

func (s *Server) exchangeBrowserSession(w http.ResponseWriter, r *http.Request) {
	if !validVersionedLocalRequest(w, r) {
		return
	}
	if len(r.Header.Values("Origin")) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": string(domain.ErrInvalidOrigin)})
		return
	}
	var request struct {
		Ticket string `json:"ticket"`
	}
	if decodeManagement(r, &request) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_BROWSER_TICKET"})
		return
	}
	sessionToken, expiresAt, ok := s.browserAuth.exchange(request.Ticket, time.Now())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "INVALID_BROWSER_TICKET"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: browserSessionCookie, Value: sessionToken, Path: "/v1/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(browserSessionTTL.Seconds())})
	writeJSON(w, http.StatusOK, map[string]string{"expires_at": expiresAt.UTC().Format(time.RFC3339)})
}

func (s *browserSessionStore) mintTicket(now time.Time) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, http.ErrServerClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	if len(s.tickets) >= maxBrowserTickets {
		return "", time.Time{}, http.ErrServerClosed
	}
	token, digest, err := randomBrowserCredential()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(browserTicketTTL)
	s.tickets[digest] = expiresAt
	return token, expiresAt, nil
}

func (s *browserSessionStore) exchange(ticket string, now time.Time) (string, time.Time, bool) {
	digest, ok := browserCredentialDigest(ticket)
	if s == nil || !ok {
		return "", time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	expiresAt, found := s.tickets[digest]
	delete(s.tickets, digest)
	if !found || !expiresAt.After(now) || len(s.sessions) >= maxBrowserSessions {
		return "", time.Time{}, false
	}
	token, sessionDigest, err := randomBrowserCredential()
	if err != nil {
		return "", time.Time{}, false
	}
	sessionExpiresAt := now.Add(browserSessionTTL)
	s.sessions[sessionDigest] = sessionExpiresAt
	return token, sessionExpiresAt, true
}

func (s *browserSessionStore) validSession(r *http.Request) bool {
	if s == nil || r == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && len(r.Header.Values("Origin")) != 1 {
		return false
	}
	cookies := r.CookiesNamed(browserSessionCookie)
	if len(cookies) != 1 {
		return false
	}
	digest, ok := browserCredentialDigest(cookies[0].Value)
	if !ok {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	return s.sessions[digest].After(now)
}

func (s *browserSessionStore) prune(now time.Time) {
	for digest, expiry := range s.tickets {
		if !expiry.After(now) {
			delete(s.tickets, digest)
		}
	}
	for digest, expiry := range s.sessions {
		if !expiry.After(now) {
			delete(s.sessions, digest)
		}
	}
}

func randomBrowserCredential() (string, [sha256.Size]byte, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(bytes[:])
	return token, sha256.Sum256([]byte(token)), nil
}

func browserCredentialDigest(value string) ([sha256.Size]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(value)), true
}

func (s *Server) identity(w http.ResponseWriter, r *http.Request) {
	if !validVersionedLocalRequest(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"api_version": APIVersion, "instance_id": s.instanceID})
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
