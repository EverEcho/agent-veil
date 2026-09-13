package session

import (
	"testing"
	"time"
)

func FuzzRouteCapabilityRequiresExactTuple(f *testing.F) {
	manager := NewManager()
	created, err := manager.Create("", "http://127.0.0.1:1", []string{"primary"}, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	wantSession := created.Session.ID
	wantRoute := created.Routes[0].RouteID
	wantToken := created.Routes[0].Token
	mutatedToken := wantToken[:len(wantToken)-1] + "0"
	if mutatedToken == wantToken {
		mutatedToken = wantToken[:len(wantToken)-1] + "1"
	}
	f.Add("", "", "")
	f.Add(wantSession, wantRoute, wantToken)
	f.Add(wantSession, wantRoute, mutatedToken)
	f.Add(wantSession, "fallback", wantToken)
	f.Fuzz(func(t *testing.T, sessionID, routeID, token string) {
		got := manager.Authorize(sessionID, routeID, token)
		want := sessionID == wantSession && routeID == wantRoute && token == wantToken
		if got != want {
			t.Fatal("route authorization did not require the exact capability tuple")
		}
	})
}
