package auth

import (
	"net/http"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

type credentials map[string]string

func (c credentials) Resolve(source string) (string, error) { return c[source], nil }

func TestAuthAppliedWithoutPersistingCredential(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://api.example/v1", nil)
	strategy := domain.AuthStrategy{Type: domain.AuthBearer, Source: "environment:API_KEY"}
	if err := (Applier{Credentials: credentials{"environment:API_KEY": "secret"}}).Apply(request, strategy); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Authorization") != "Bearer secret" {
		t.Fatal("bearer auth missing")
	}
	if strategy.Source == "secret" {
		t.Fatal("strategy persisted the credential")
	}
}
