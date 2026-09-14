package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/agentveil/agentveil/internal/session"
)

func TestBrowserTicketCreatesOneTimeHttpOnlyManagementSession(t *testing.T) {
	const adminToken = "01234567890123456789012345678901"
	server, err := New(session.NewManager(), adminToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())

	unauthenticatedMint, _ := http.NewRequest(http.MethodPost, server.Endpoint()+"/v1/browser-sessions", nil)
	unauthenticatedMint.Header.Set(APIVersionHeader, APIVersion)
	response, err := http.DefaultClient.Do(unauthenticatedMint)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated mint response=%v error=%v", response, err)
	}
	response.Body.Close()

	mint, _ := http.NewRequest(http.MethodPost, server.Endpoint()+"/v1/browser-sessions", nil)
	mint.Header.Set(APIVersionHeader, APIVersion)
	mint.Header.Set("Authorization", "Bearer "+adminToken)
	response, err = http.DefaultClient.Do(mint)
	if err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("mint response=%v error=%v", response, err)
	}
	var issued struct {
		Ticket    string `json:"ticket"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if len(issued.Ticket) != 43 || issued.ExpiresAt == "" {
		t.Fatalf("issued=%+v", issued)
	}

	payload, _ := json.Marshal(map[string]string{"ticket": issued.Ticket})
	missingOrigin, _ := http.NewRequest(http.MethodPost, server.Endpoint()+"/v1/browser-sessions/exchange", bytes.NewReader(payload))
	missingOrigin.Header.Set(APIVersionHeader, APIVersion)
	missingOrigin.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(missingOrigin)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("originless exchange response=%v error=%v", response, err)
	}
	response.Body.Close()

	cookie := exchangeBrowserTicket(t, server.Endpoint(), issued.Ticket, http.StatusOK)
	if cookie == nil || cookie.Name != browserSessionCookie || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/v1/" || cookie.MaxAge <= 0 {
		t.Fatalf("browser session cookie=%+v", cookie)
	}
	exchangeBrowserTicket(t, server.Endpoint(), issued.Ticket, http.StatusUnauthorized)

	health, _ := http.NewRequest(http.MethodGet, server.Endpoint()+"/v1/health", nil)
	health.Header.Set(APIVersionHeader, APIVersion)
	health.AddCookie(cookie)
	response, err = http.DefaultClient.Do(health)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("cookie-authenticated health response=%v error=%v", response, err)
	}
	response.Body.Close()

	mutation, _ := http.NewRequest(http.MethodPut, server.Endpoint()+"/v1/policy", bytes.NewBufferString(`{"version":"v1"}`))
	mutation.Header.Set(APIVersionHeader, APIVersion)
	mutation.Header.Set("Content-Type", "application/json")
	mutation.AddCookie(cookie)
	response, err = http.DefaultClient.Do(mutation)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cookie mutation without explicit Origin response=%v error=%v", response, err)
	}
	response.Body.Close()
}

func exchangeBrowserTicket(t *testing.T, endpoint, ticket string, expectedStatus int) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"ticket": ticket})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, endpoint+"/v1/browser-sessions/exchange", bytes.NewReader(payload))
	request.Header.Set(APIVersionHeader, APIVersion)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", endpoint)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != expectedStatus {
		t.Fatalf("exchange status=%v response=%v error=%v", expectedStatus, response, err)
	}
	defer response.Body.Close()
	for _, cookie := range response.Cookies() {
		if cookie.Name == browserSessionCookie {
			return cookie
		}
	}
	return nil
}
