package auth

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type credentials map[string]string

func (c credentials) Resolve(source string) (string, error) { return c[source], nil }

func TestAuthAppliedWithoutPersistingCredential(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://api.example/v1?key=stale", nil)
	request.Header.Set("Authorization", "Bearer stale")
	request.Header.Set("X-Api-Key", "stale")
	strategy := domain.AuthStrategy{Type: domain.AuthBearer, Source: "environment:API_KEY"}
	if err := (Applier{Credentials: credentials{"environment:API_KEY": "secret"}}).Apply(request, strategy); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Authorization") != "Bearer secret" {
		t.Fatal("bearer auth missing")
	}
	if request.Header.Get("X-Api-Key") != "" || request.URL.Query().Get("key") != "" {
		t.Fatal("stale client credentials survived configured authentication")
	}
	if strategy.Source == "secret" {
		t.Fatal("strategy persisted the credential")
	}
}

type awsCredentials struct{}

func (awsCredentials) ResolveAWS(string) (AWSCredentials, error) {
	return AWSCredentials{AccessKey: "AKIDEXAMPLE", SecretKey: "secret", SessionToken: "session"}, nil
}

func TestSigV4SignsFinalBodyAndPreservesIt(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://bedrock.us-east-1.amazonaws.com/model/invoke", strings.NewReader(`{"input":"redacted"}`))
	signer := AWSSigner{Region: "us-east-1", Service: "bedrock", Credentials: awsCredentials{}, Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }}
	applier := Applier{Signers: map[domain.AuthType]Signer{domain.AuthAWSSigV4: signer}}
	if err := applier.Apply(request, domain.AuthStrategy{Type: domain.AuthAWSSigV4}); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	if string(body) != `{"input":"redacted"}` || !strings.Contains(request.Header.Get("Authorization"), "Credential=AKIDEXAMPLE/20260102/us-east-1/bedrock/aws4_request") || request.Header.Get("X-Amz-Security-Token") != "session" {
		t.Fatalf("headers=%v body=%s", request.Header, body)
	}
}
