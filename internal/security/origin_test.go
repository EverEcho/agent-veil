package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoopbackAuthorityAndOriginValidation(t *testing.T) {
	for _, authority := range []string{"127.0.0.1:43123", "[::1]:43123", "localhost:43123"} {
		if !ValidLoopbackAuthority(authority) {
			t.Fatalf("loopback authority rejected: %s", authority)
		}
	}
	for _, authority := range []string{"attacker.example", "127.0.0.1@attacker.example", "127.0.0.1/path", ""} {
		if ValidLoopbackAuthority(authority) {
			t.Fatalf("unsafe authority accepted: %q", authority)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:43123/v1/health", nil)
	request.Header.Set("Origin", "http://127.0.0.1:43123")
	if !ValidLocalOrigin(request) {
		t.Fatal("same loopback origin was rejected")
	}
	for _, origin := range []string{"https://127.0.0.1:43123", "http://localhost:43123", "https://attacker.example", "null"} {
		request.Header.Set("Origin", origin)
		if ValidLocalOrigin(request) {
			t.Fatalf("unsafe origin accepted: %q", origin)
		}
	}
	request.Header["Origin"] = []string{"http://127.0.0.1:43123", "https://attacker.example"}
	if ValidLocalOrigin(request) {
		t.Fatal("duplicate Origin headers were accepted")
	}
	request.Header["Origin"] = []string{""}
	if ValidLocalOrigin(request) {
		t.Fatal("explicit empty Origin header was accepted")
	}
	if ValidLocalOrigin(nil) {
		t.Fatal("nil request was accepted")
	}
}
