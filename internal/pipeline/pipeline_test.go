package pipeline

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

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
	if strings.Contains(result.Preview, "dev@example.com") || strings.Contains(result.Preview, "13800138000") || !strings.Contains(result.Preview, "contact *** or ***") {
		t.Fatalf("unsafe or missing audit preview: %q", result.Preview)
	}
	restored, err := vault.Restore(string(result.Body))
	if err != nil || !strings.Contains(restored, "dev@example.com") {
		t.Fatalf("restore failed: %v %s", err, restored)
	}
}

func TestAuditPreviewIsBoundedAroundLatestProtectedFragment(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	text := strings.Repeat("前文", 120) + " 这是邮箱 dev@example.com ，请帮我处理 " + strings.Repeat("后文", 120)
	result, err := Process(Context{}, "/v1/responses", "application/json", "", []byte(`{"input":`+strconv.Quote(text)+`}`), detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault)
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(result.Preview) > maxAuditPreviewRunes+2 || !strings.Contains(result.Preview, "这是邮箱 ***") || strings.Contains(result.Preview, "dev@example.com") {
		t.Fatalf("preview=%q", result.Preview)
	}
}

func TestEscapedEmailInCodexPromptIsStillRedacted(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	text := `这个是测试邮箱 privacy-test\@example.invalid ，请逐字返回`
	result, err := Process(Context{}, "/responses", "application/json", "", []byte(`{"input":`+strconv.Quote(text)+`}`), detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Body), "privacy-test") || !strings.Contains(string(result.Body), "[[VEIL_PII_EMAIL_") {
		t.Fatalf("upstream-bound body was not protected: %s", result.Body)
	}
	if strings.Contains(result.Preview, "privacy-test") || !strings.Contains(result.Preview, `邮箱 ***`) {
		t.Fatalf("preview=%q", result.Preview)
	}
}

func TestEnvironmentBlockRedactsValuesWithoutDamagingVariableNames(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 2048})
	values := []string{
		"0f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"f1e2d3c4b5a69788796a5b4c3d2e1f00",
		"SyntheticCloudSecret9x7v5t3r1p",
	}
	text := strings.Join([]string{
		"env=dev",
		"USER\\_AES\\_IV=" + values[0],
		"USER\\_AES\\_KEY=" + values[1],
		"ALIYUN\\_OSS\\_ACCESS\\_KEY\\_SECRET=" + values[2],
		"BASE\\_URL=https://service.example.invalid/v1",
	}, "\n")
	result, err := ProcessText(Context{}, "/input", text, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if strings.Contains(result.Text, value) || strings.Contains(result.Preview, value) {
			t.Fatalf("environment secret leaked: text=%q preview=%q", result.Text, result.Preview)
		}
	}
	for _, name := range []string{"USER\\_AES\\_IV=", "USER\\_AES\\_KEY=", "ALIYUN\\_OSS\\_ACCESS\\_KEY\\_SECRET="} {
		if !strings.Contains(result.Text, name+"[[VEIL_SECRET_ASSIGNMENT_") {
			t.Fatalf("variable name or assignment syntax changed: %q", result.Text)
		}
	}
	if !strings.Contains(result.Text, "env=dev") || !strings.Contains(result.Text, "BASE\\_URL=https://service.example.invalid/v1") {
		t.Fatalf("ordinary environment configuration changed: %q", result.Text)
	}
}

func TestTextIsRedactedWithoutRemovingHeaderSemantics(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	original := "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlMTIzNDU2"
	result, err := ProcessText(Context{}, "/request/headers/X-Debug", original, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Text, "Bearer [[VEIL_") || strings.Contains(result.Text, "eyJhbGci") || len(result.Findings) == 0 || len(result.Actions) != len(result.Findings) {
		t.Fatalf("header semantics or metadata lost: %+v", result)
	}
	restored, err := vault.Restore(result.Text)
	if err != nil || restored != original {
		t.Fatalf("restored=%q err=%v", restored, err)
	}
}

type redactApprover struct{}

func (redactApprover) Request(context.Context, domain.Finding) (domain.Action, error) {
	return domain.ActionRedact, nil
}
func TestInteractiveASKCanResolveToRedact(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	result, err := Process(Context{Interactive: true, RequestContext: context.Background(), Approver: redactApprover{}}, "/v1/responses", "application/json", "", []byte(`{"input":"dev@example.com"}`), detector.NewDefault(), policy.Engine{Default: domain.ActionAsk}, vault)
	if err != nil || strings.Contains(string(result.Body), "dev@example.com") {
		t.Fatalf("result=%s err=%v", result.Body, err)
	}
}

func TestPrivateKeyFailsClosed(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	_, err := Process(Context{}, "/v1/chat/completions", "application/json", "", []byte(`{"messages":[{"role":"user","content":"-----BEGIN PRIVATE KEY-----"}]}`), detector.NewDefault(), policy.Engine{Default: domain.ActionRedact, Rules: []policy.Rule{{Scope: policy.Scope{FindingType: "secret.private_key"}, Action: domain.ActionBlock}}}, vault)
	if err == nil {
		t.Fatal("private key was not blocked")
	}
}

func TestNestedJSONStringToolArgumentsAreRedactedAndRemainTyped(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024})
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"notify","arguments":"{\"contact\":\"dev@example.com\",\"nested\":\"{\\\"phone\\\":\\\"13800138000\\\"}\"}"}}]}]}`)
	result, err := Process(Context{}, "/v1/chat/completions", "application/json", "", body, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Body), "dev@example.com") || strings.Contains(string(result.Body), "13800138000") {
		t.Fatalf("nested sensitive value leaked: %s", result.Body)
	}
	var outer map[string]any
	if err := json.Unmarshal(result.Body, &outer); err != nil {
		t.Fatal(err)
	}
	messages := outer["messages"].([]any)
	call := messages[0].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	arguments, ok := call["function"].(map[string]any)["arguments"].(string)
	if !ok || !json.Valid([]byte(arguments)) {
		t.Fatalf("arguments type or JSON content changed: %#v", call)
	}
}
