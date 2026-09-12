package session

import (
	"strings"
	"testing"
	"time"
)

func TestRouteAuthorizationAndExpiry(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	created, err := m.Create("", "http://127.0.0.1:1", []string{"primary", "fallback"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Authorize(created.Session.ID, "primary", created.Routes[0].Token) {
		t.Fatal("valid capability rejected")
	}
	if m.Authorize(created.Session.ID, "fallback", created.Routes[0].Token) {
		t.Fatal("route token was reusable on another route")
	}
	now = now.Add(2 * time.Minute)
	if m.Authorize(created.Session.ID, "primary", created.Routes[0].Token) {
		t.Fatal("expired session authorized")
	}
	if len(m.List()) != 0 {
		t.Fatal("expired session not cleaned")
	}
}

func TestManagerEnforcesTTLRouteAndActiveSessionLimits(t *testing.T) {
	m, err := NewManagerWithLimits(Limits{MaxSessions: 2, MaxRoutes: 2, MaxTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	if _, err := m.Create("", "local", []string{"route"}, time.Minute+time.Second); err == nil {
		t.Fatal("overlong session TTL was accepted")
	}
	if _, err := m.Create("", "local", []string{"one", "two", "three"}, time.Minute); err == nil {
		t.Fatal("excess route count was accepted")
	}
	first, err := m.Create("", "local", []string{"one"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("", "local", []string{"two"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("", "local", []string{"three"}, time.Minute); err == nil {
		t.Fatal("active session capacity was exceeded")
	}
	now = now.Add(2 * time.Second)
	if _, err := m.Create("", "local", []string{"three"}, time.Minute); err != nil {
		t.Fatalf("expired capacity was not reclaimed: %v", err)
	}
	if m.Authorize(first.Session.ID, "one", first.Routes[0].Token) {
		t.Fatal("expired session remained authorized after capacity pruning")
	}
}

func TestManagerRejectsInvalidLimits(t *testing.T) {
	for _, limits := range []Limits{
		{},
		{MaxSessions: 1, MaxRoutes: 1, MaxTTL: 0},
		{MaxSessions: 1, MaxRoutes: 0, MaxTTL: time.Minute},
		{MaxSessions: 0, MaxRoutes: 1, MaxTTL: time.Minute},
	} {
		if _, err := NewManagerWithLimits(limits); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid limits accepted or unsafe error returned: %+v err=%v", limits, err)
		}
	}
}

func TestRouteAuthorizationReturnsSessionExpiry(t *testing.T) {
	m := NewManager()
	created, err := m.Create("", "local", []string{"primary"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorization, ok := m.AuthorizeRoute(created.Session.ID, "primary", created.Routes[0].Token)
	if !ok || len(authorization.Secret) != 32 || !authorization.ExpiresAt.Equal(created.Session.ExpiresAt) || authorization.Context == nil {
		t.Fatalf("authorized=%v secret-bytes=%d expires=%v want=%v", ok, len(authorization.Secret), authorization.ExpiresAt, created.Session.ExpiresAt)
	}
	if !m.Delete(created.Session.ID) {
		t.Fatal("session was not deleted")
	}
	select {
	case <-authorization.Context.Done():
	default:
		t.Fatal("route authorization was not revoked with its session")
	}
}

func TestChildSessionRequiresLiveParentAndCannotOutliveIt(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	if _, err := m.Create("missing", "local", []string{"child"}, time.Minute); err == nil {
		t.Fatal("missing parent was accepted")
	}
	parent, err := m.Create("", "local", []string{"parent"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(parent.Session.SessionSecret()) != 0 {
		t.Fatal("created session exposed its internal secret")
	}
	if _, err := m.Create(parent.Session.ID, "local", []string{"child"}, 2*time.Minute); err == nil {
		t.Fatal("child was allowed to outlive parent")
	}
	child, err := m.Create(parent.Session.ID, "local", []string{"child"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	listed := m.List()
	if len(listed) != 2 || len(listed[0].SessionSecret()) != 0 || len(listed[1].SessionSecret()) != 0 {
		t.Fatalf("public session list exposed secrets: %+v", listed)
	}
	if !m.Delete(parent.Session.ID) || m.Authorize(child.Session.ID, "child", child.Routes[0].Token) || len(m.List()) != 0 {
		t.Fatal("deleting parent did not revoke descendants")
	}
}

func TestExpiredAuthorizationImmediatelyRemovesSession(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	created, _ := m.Create("", "local", []string{"primary"}, time.Second)
	now = now.Add(2 * time.Second)
	if m.Authorize(created.Session.ID, "primary", created.Routes[0].Token) {
		t.Fatal("expired capability authorized")
	}
	m.mu.RLock()
	_, retained := m.sessions[created.Session.ID]
	m.mu.RUnlock()
	if retained {
		t.Fatal("expired session secret remained resident after authorization")
	}
}

func TestPruneExpiredRevokesIdleParentAndChildSessions(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	parent, _ := m.Create("", "local", []string{"parent"}, time.Minute)
	child, _ := m.Create(parent.Session.ID, "local", []string{"child"}, 30*time.Second)
	authorization, ok := m.AuthorizeRoute(child.Session.ID, "child", child.Routes[0].Token)
	if !ok {
		t.Fatal("child authorization failed")
	}
	now = now.Add(2 * time.Minute)
	if removed := m.PruneExpired(); removed != 2 {
		t.Fatalf("removed=%d", removed)
	}
	select {
	case <-authorization.Context.Done():
	default:
		t.Fatal("idle child authorization was not revoked")
	}
	if len(m.sessions) != 0 {
		t.Fatalf("expired sessions retained=%d", len(m.sessions))
	}
}
