package pipeline

import (
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
)

func TestRequestIsRedactedAndRecoverable(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	result, err := Process(Context{AgentID: "codex", SurfaceID: "primary"}, "/v1/responses", "application/json", "", []byte(`{"input":"contact dev@example.com or 13800138000","model":"gpt"}`), detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Body), "dev@example.com") || strings.Contains(string(result.Body), "13800138000") {
		t.Fatalf("sensitive value leaked: %s", result.Body)
	}
	restored, err := vault.Restore(string(result.Body))
	if err != nil || !strings.Contains(restored, "dev@example.com") {
		t.Fatalf("restore failed: %v %s", err, restored)
	}
}

func TestPrivateKeyFailsClosed(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	_, err := Process(Context{}, "/v1/chat/completions", "application/json", "", []byte(`{"messages":[{"role":"user","content":"-----BEGIN PRIVATE KEY-----"}]}`), detector.NewDefault(), policy.Engine{Default: domain.ActionRedact, Rules: []policy.Rule{{Scope: policy.Scope{FindingType: "secret.private_key"}, Action: domain.ActionBlock}}}, vault)
	if err == nil {
		t.Fatal("private key was not blocked")
	}
}
