package auth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestEnvironmentCredentialsRequireIndirectNamedSource(t *testing.T) {
	t.Setenv("VEIL_TEST_PROVIDER_TOKEN", "provider-secret")
	resolver := EnvironmentCredentials{}
	value, err := resolver.Resolve("environment:VEIL_TEST_PROVIDER_TOKEN")
	if err != nil || value != "provider-secret" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	for _, source := range []string{"provider-secret", "environment:", "environment:lowercase", "environment:BAD-NAME"} {
		if _, err := resolver.Resolve(source); err == nil {
			t.Fatalf("unsafe source accepted: %q", source)
		}
	}
}

func TestRuntimeApplierBuildsBedrockSignerFromEndpoint(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	upstream, _ := url.Parse("https://bedrock-runtime.us-east-1.amazonaws.com")
	applier, err := NewRuntimeApplier(domain.AuthStrategy{Type: domain.AuthAWSSigV4, Source: "environment:aws-default"}, upstream)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, upstream.String()+"/model/test/invoke", strings.NewReader(`{"input":"redacted"}`))
	if err := applier.Apply(request, domain.AuthStrategy{Type: domain.AuthAWSSigV4}); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	if string(body) != `{"input":"redacted"}` || !strings.Contains(request.Header.Get("Authorization"), "/us-east-1/bedrock/aws4_request") {
		t.Fatalf("headers=%v body=%s", request.Header, body)
	}
}

func TestRuntimeApplierRejectsUnconfiguredCustomAndUnknownAWSHosts(t *testing.T) {
	upstream, _ := url.Parse("https://api.example")
	for _, strategy := range []domain.AuthStrategy{{Type: domain.AuthCustom}, {Type: domain.AuthAWSSigV4}} {
		if _, err := NewRuntimeApplier(strategy, upstream); err == nil {
			t.Fatalf("strategy accepted: %+v", strategy)
		}
	}
}
