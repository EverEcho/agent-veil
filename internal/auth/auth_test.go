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

func TestResolvedCredentialsMustBeBoundedVisibleASCII(t *testing.T) {
	for name, value := range map[string]string{
		"empty":      "",
		"space":      "provider secret",
		"tab":        "provider\tsecret",
		"newline":    "provider\nsecret",
		"non-ascii":  "密钥",
		"over-limit": strings.Repeat("x", MaxCredentialBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, "https://api.example/v1", nil)
			err := (Applier{Credentials: credentials{"environment:API_KEY": value}}).Apply(request, domain.AuthStrategy{Type: domain.AuthBearer, Source: "environment:API_KEY"})
			if err == nil || request.Header.Get("Authorization") != "" {
				t.Fatalf("credential accepted or installed: error=%v headers=%v", err, request.Header)
			}
		})
	}
}

type awsCredentials struct{}

func (awsCredentials) ResolveAWS(string) (AWSCredentials, error) {
	return AWSCredentials{AccessKey: "AKIDEXAMPLE", SecretKey: "secret", SessionToken: "session"}, nil
}

type invalidAWSCredentials struct{ credentials AWSCredentials }

func (c invalidAWSCredentials) ResolveAWS(string) (AWSCredentials, error) { return c.credentials, nil }

func TestSigV4RejectsMalformedCredentialMaterial(t *testing.T) {
	for name, candidate := range map[string]AWSCredentials{
		"access key control": {AccessKey: "AKID\nEXAMPLE", SecretKey: "secret"},
		"secret whitespace":  {AccessKey: "AKIDEXAMPLE", SecretKey: "secret value"},
		"session control":    {AccessKey: "AKIDEXAMPLE", SecretKey: "secret", SessionToken: "session\rvalue"},
		"oversized session":  {AccessKey: "AKIDEXAMPLE", SecretKey: "secret", SessionToken: strings.Repeat("x", MaxCredentialBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, "https://bedrock.us-east-1.amazonaws.com/model/invoke", strings.NewReader(`{"input":"redacted"}`))
			signer := AWSSigner{Region: "us-east-1", Service: "bedrock", Credentials: invalidAWSCredentials{credentials: candidate}}
			if err := signer.Apply(request); err == nil || request.Header.Get("Authorization") != "" {
				t.Fatalf("malformed credentials accepted: headers=%v error=%v", request.Header, err)
			}
		})
	}
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

func TestAuthenticationRejectsMissingOrOversizedRequests(t *testing.T) {
	if err := (Applier{}).Apply(nil, domain.AuthStrategy{Type: domain.AuthPassthrough}); err == nil {
		t.Fatal("nil request was accepted")
	}
	request, _ := http.NewRequest(http.MethodPost, "https://bedrock.us-east-1.amazonaws.com/model/invoke", strings.NewReader("123456789"))
	request.ContentLength = -1
	signer := AWSSigner{Region: "us-east-1", Service: "bedrock", Credentials: awsCredentials{}, MaxBodyBytes: 8}
	if err := signer.Apply(request); err == nil || request.Header.Get("Authorization") != "" {
		t.Fatalf("oversized signing body accepted: headers=%v error=%v", request.Header, err)
	}
	empty, _ := http.NewRequest(http.MethodPost, "https://bedrock.us-east-1.amazonaws.com/model/invoke", nil)
	if err := signer.Apply(empty); err != nil || empty.Header.Get("Authorization") == "" {
		t.Fatalf("empty signing body rejected: headers=%v error=%v", empty.Header, err)
	}
}
