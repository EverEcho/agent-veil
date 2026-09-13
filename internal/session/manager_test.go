package session

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type recordingFailReader struct {
	calls  int
	failAt int
	seen   [][]byte
}

func (r *recordingFailReader) Read(buffer []byte) (int, error) {
	r.calls++
	for index := range buffer {
		buffer[index] = byte(r.calls)
	}
	r.seen = append(r.seen, buffer)
	if r.calls == r.failAt {
		return len(buffer) / 2, errors.New("random source failed")
	}
	return len(buffer), nil
}

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

func TestSessionListIsStableBySessionID(t *testing.T) {
	m := NewManager()
	for range 4 {
		if _, err := m.Create("", "local", []string{"primary"}, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	listed := m.List()
	for index := 1; index < len(listed); index++ {
		if listed[index-1].ID >= listed[index].ID {
			t.Fatalf("unstable session order: %+v", listed)
		}
	}
}

func TestDeleteRoutesCancelsMatchingSessionTreesOnly(t *testing.T) {
	m := NewManager()
	parent, err := m.Create("", "local", []string{"route-a"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	child, err := m.Create(parent.Session.ID, "local", []string{"route-a"}, time.Minute-time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := m.Create("", "local", []string{"route-b"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parentAuthorization, _ := m.AuthorizeRoute(parent.Session.ID, "route-a", parent.Routes[0].Token)
	childAuthorization, _ := m.AuthorizeRoute(child.Session.ID, "route-a", child.Routes[0].Token)
	if removed := m.DeleteRoutes([]string{"route-a", "route-a", "../invalid"}); removed != 2 {
		t.Fatalf("removed sessions=%d", removed)
	}
	for _, authorization := range []Authorization{parentAuthorization, childAuthorization} {
		select {
		case <-authorization.Context.Done():
		default:
			t.Fatal("matching in-flight route authorization was not cancelled")
		}
	}
	if !m.Authorize(unrelated.Session.ID, "route-b", unrelated.Routes[0].Token) || len(m.List()) != 1 {
		t.Fatalf("unrelated session was revoked: %+v", m.List())
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
		{MaxSessions: MaximumSessions + 1, MaxRoutes: 1, MaxTTL: time.Minute},
		{MaxSessions: 1, MaxRoutes: MaximumRoutes + 1, MaxTTL: time.Minute},
		{MaxSessions: 1, MaxRoutes: 1, MaxTTL: MaximumTTL + time.Second},
	} {
		if _, err := NewManagerWithLimits(limits); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid limits accepted or unsafe error returned: %+v err=%v", limits, err)
		}
	}
}

func TestManagerRejectsUnsafeSessionReferences(t *testing.T) {
	m := NewManager()
	invalidUTF8 := string([]byte{0xff})
	for _, endpoint := range []string{"", strings.Repeat("x", maxEndpointBytes+1), "local\x00endpoint", invalidUTF8} {
		if _, err := m.Create("", endpoint, []string{"route"}, time.Minute); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	for _, routeID := range []string{"", "unsafe route", "../route", strings.Repeat("r", 129)} {
		if _, err := m.Create("", "local", []string{routeID}, time.Minute); err == nil {
			t.Fatalf("unsafe route id accepted: %q", routeID)
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

func TestInteractionCapabilityDefaultsOffAndCannotEscalateInChildren(t *testing.T) {
	m := NewManager()
	nonInteractive, err := m.Create("", "local", []string{"primary"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorization, ok := m.AuthorizeRoute(nonInteractive.Session.ID, "primary", nonInteractive.Routes[0].Token)
	if !ok || authorization.Interactive || nonInteractive.Session.Interactive {
		t.Fatalf("non-interactive session gained interaction capability: session=%+v auth=%+v", nonInteractive.Session, authorization)
	}
	if _, err := m.CreateWithOptions(nonInteractive.Session.ID, "local", []string{"primary"}, time.Second, CreateOptions{Interactive: true}); err == nil {
		t.Fatal("child escalated interaction capability")
	}
	interactive, err := m.CreateWithOptions("", "local", []string{"interactive"}, time.Minute, CreateOptions{Interactive: true})
	if err != nil {
		t.Fatal(err)
	}
	authorization, ok = m.AuthorizeRoute(interactive.Session.ID, "interactive", interactive.Routes[0].Token)
	if !ok || !authorization.Interactive || !interactive.Session.Interactive {
		t.Fatalf("explicit interaction capability was lost: session=%+v auth=%+v", interactive.Session, authorization)
	}
}

func TestDeletingSessionOverwritesInternalRouteCapabilities(t *testing.T) {
	m := NewManager()
	created, err := m.Create("", "local", []string{"primary"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	internalToken := m.sessions[created.Session.ID].routes[0].token
	m.mu.RUnlock()
	if len(internalToken) == 0 {
		t.Fatal("internal route capability was not retained")
	}
	if !m.Delete(created.Session.ID) {
		t.Fatal("session was not deleted")
	}
	for _, value := range internalToken {
		if value != 0 {
			t.Fatal("internal route capability bytes survived deletion")
		}
	}
}

func TestSessionCreationWipesPartialCapabilitiesAfterRandomFailure(t *testing.T) {
	for _, failAt := range []int{2, 4} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			m := NewManager()
			reader := &recordingFailReader{failAt: failAt}
			m.random = reader
			_, err := m.Create("", "local", []string{"primary", "fallback"}, time.Minute)
			if err == nil || !strings.Contains(err.Error(), "secure randomness is unavailable") {
				t.Fatalf("random failure result=%v", err)
			}
			if len(m.sessions) != 0 {
				t.Fatal("failed session was retained")
			}
			for call, buffer := range reader.seen {
				for _, value := range buffer {
					if value != 0 {
						t.Fatalf("random buffer from call %d survived failure", call+1)
					}
				}
			}
		})
	}
}

func TestSessionCreationWipesTemporaryRandomBuffersAfterSuccess(t *testing.T) {
	m := NewManager()
	reader := &recordingFailReader{}
	m.random = reader
	created, err := m.Create("", "local", []string{"primary", "fallback"}, time.Minute)
	if err != nil || !m.Authorize(created.Session.ID, "primary", created.Routes[0].Token) {
		t.Fatalf("created=%+v error=%v", created, err)
	}
	for call, buffer := range reader.seen {
		for _, value := range buffer {
			if value != 0 {
				t.Fatalf("temporary random buffer from call %d survived successful creation", call+1)
			}
		}
	}
}

var _ io.Reader = (*recordingFailReader)(nil)

func TestChildSessionRequiresLiveParentAndCannotOutliveIt(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	if _, err := m.Create("missing", "local", []string{"child"}, time.Minute); err == nil {
		t.Fatal("missing parent was accepted")
	}
	parent, err := m.Create("", "local", []string{"primary", "fallback"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(parent.Session.SessionSecret()) != 0 {
		t.Fatal("created session exposed its internal secret")
	}
	if _, err := m.Create(parent.Session.ID, "local", []string{"primary"}, 2*time.Minute); err == nil {
		t.Fatal("child was allowed to outlive parent")
	}
	if _, err := m.Create(parent.Session.ID, "other-core", []string{"primary"}, 30*time.Second); err == nil {
		t.Fatal("child was allowed to switch Core endpoints")
	}
	if _, err := m.Create(parent.Session.ID, "local", []string{"primary", "unowned"}, 30*time.Second); err == nil {
		t.Fatal("child was allowed to add a route outside its parent")
	}
	child, err := m.Create(parent.Session.ID, "local", []string{"fallback"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Session.RouteIDs) != 1 || child.Session.RouteIDs[0] != "fallback" {
		t.Fatalf("child did not retain the requested parent-route subset: %+v", child.Session.RouteIDs)
	}
	listed := m.List()
	if len(listed) != 2 || len(listed[0].SessionSecret()) != 0 || len(listed[1].SessionSecret()) != 0 {
		t.Fatalf("public session list exposed secrets: %+v", listed)
	}
	if !m.Delete(parent.Session.ID) || m.Authorize(child.Session.ID, "fallback", child.Routes[0].Token) || len(m.List()) != 0 {
		t.Fatal("deleting parent did not revoke descendants")
	}
}

func TestBoundedChildSessionAtomicallyInheritsParentExpiry(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	parent, err := m.Create("", "local", []string{"primary"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Second)
	child, err := m.CreateChildWithin(parent.Session.ID, "local", []string{"primary"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !child.Session.ExpiresAt.Equal(parent.Session.ExpiresAt) || child.Session.Interactive {
		t.Fatalf("bounded child did not inherit the parent expiry: parent=%v child=%+v", parent.Session.ExpiresAt, child.Session)
	}
	if _, err := m.CreateChildWithin("", "local", []string{"primary"}, time.Second); err == nil {
		t.Fatal("bounded child creation accepted an empty parent")
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
	child, _ := m.Create(parent.Session.ID, "local", []string{"parent"}, 30*time.Second)
	authorization, ok := m.AuthorizeRoute(child.Session.ID, "parent", child.Routes[0].Token)
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

func TestContainsRouteValidatesLiveManagementOwnership(t *testing.T) {
	m := NewManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	created, err := m.Create("", "local", []string{"primary"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ContainsRoute(created.Session.ID, "primary") || m.ContainsRoute(created.Session.ID, "other") || m.ContainsRoute("missing", "primary") {
		t.Fatal("live route ownership was not validated exactly")
	}
	now = now.Add(2 * time.Second)
	if m.ContainsRoute(created.Session.ID, "primary") || len(m.List()) != 0 {
		t.Fatal("expired route ownership remained valid")
	}
}

func TestOnlySingleRouteChildCanRevokeItself(t *testing.T) {
	m := NewManager()
	parent, err := m.Create("", "local", []string{"primary", "fallback"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	child, err := m.Create(parent.Session.ID, "local", []string{"primary"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := m.Create(child.Session.ID, "local", []string{"primary"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m.DeleteChildAuthorized(parent.Session.ID, "primary", parent.Routes[0].Token) {
		t.Fatal("root session revoked itself through child authority")
	}
	if m.DeleteChildAuthorized(child.Session.ID, "primary", parent.Routes[0].Token) {
		t.Fatal("parent route token revoked a child session")
	}
	if !m.DeleteChildAuthorized(child.Session.ID, "primary", child.Routes[0].Token) {
		t.Fatal("single-route child could not revoke itself")
	}
	if !m.Authorize(parent.Session.ID, "primary", parent.Routes[0].Token) || m.Authorize(grandchild.Session.ID, "primary", grandchild.Routes[0].Token) {
		t.Fatal("child self-revocation affected its parent or retained its descendant")
	}
}
