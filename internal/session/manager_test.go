package session

import (
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
