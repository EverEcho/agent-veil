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
