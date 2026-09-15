package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/feedback"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/session"
)

type failingAuditor struct{}

func TestHealthReportsAuditPersistenceFailures(t *testing.T) {
	s, err := New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	s.WithAuditor(failingAuditor{})
	if err := s.auditor.Append(domain.AuditEvent{}); err == nil {
		t.Fatal("failing auditor unexpectedly succeeded")
	}
	recorder := httptest.NewRecorder()
	s.health(recorder, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var health map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "degraded" || health["audit"] != "error" || health["audit_failures"] != "1" {
		t.Fatalf("health=%+v", health)
	}
}

func TestDashboardUsesSharedBeginnerUIWithoutProtectedData(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")

	index := httptest.NewRecorder()
	s.dashboard(index, httptest.NewRequest(http.MethodGet, "/", nil))
	if index.Code != http.StatusOK || strings.Contains(index.Body.String(), "01234567890123456789012345678901") {
		t.Fatal("dashboard failed or leaked management data")
	}
	assertLocalSecurityHeaders(t, index.Header())
	csp := index.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "style-src 'self'") || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "base-uri 'none'") {
		t.Fatalf("dashboard CSP=%q", csp)
	}
	for _, required := range []string{"lang=\"zh-CN\"", "需要本机浏览器会话", "veil web", "我的工具", "保护记录", "隐私保护", "敏感环境变量", "疑似未知密钥", "data-protection-setting=\"contact\"", "高级功能", "src=\"/app.js\"", "href=\"/styles.css\"", "href=\"/visibility.css\""} {
		if !strings.Contains(index.Body.String(), required) {
			t.Fatalf("dashboard shell is missing %q", required)
		}
	}
	if strings.Contains(index.Body.String(), "id=\"token\"") || strings.Contains(index.Body.String(), "管理令牌</label>") {
		t.Fatal("dashboard still exposes manual management-token input")
	}

	for _, asset := range []struct {
		path        string
		contentType string
		required    []string
	}{
		{path: "/styles.css", contentType: "text/css; charset=utf-8", required: []string{".app-shell", ".tool-grid", "prefers-reduced-motion"}},
		{path: "/visibility.css", contentType: "text/css; charset=utf-8", required: []string{"[hidden]", "!important"}},
		{path: "/app.js", contentType: "text/javascript; charset=utf-8", required: []string{"/v1/discovery", "/v1/policy", "protectionSettingGroups", "secret.assignment", "secret.high_entropy", "Promise.all", "Array.isArray", "requestCore", "startBrowserSession", "downloadDiagnostics", "保护范围", "AI 对话", "本地工具（", "当前保护什么", "可以开始保护"}},
		{path: "/platform.js", contentType: "text/javascript; charset=utf-8", required: []string{"core_request", "browser-sessions/exchange", "credentials:'same-origin'", "X-AgentVeil-API-Version"}},
	} {
		recorder := httptest.NewRecorder()
		s.dashboard(recorder, httptest.NewRequest(http.MethodGet, asset.path, nil))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != asset.contentType {
			t.Fatalf("asset %s status=%d type=%q", asset.path, recorder.Code, recorder.Header().Get("Content-Type"))
		}
		assertLocalSecurityHeaders(t, recorder.Header())
		for _, required := range asset.required {
			if !strings.Contains(recorder.Body.String(), required) {
				t.Fatalf("asset %s is missing %q", asset.path, required)
			}
		}
	}
	app := httptest.NewRecorder()
	s.dashboard(app, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	for _, developerCopy := range []string{"兼容性证据", "受保护启动烟测", "保护边界：主模型连接", "可检查的连接"} {
		if strings.Contains(app.Body.String(), developerCopy) {
			t.Fatalf("dashboard still exposes developer copy %q", developerCopy)
		}
	}
}

func TestDetectionTestAPIReportsMetadataWithoutEchoingOriginal(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	request := httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"contact dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "dev@example.com") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response detectionTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 || response.Results[0].Finding.Category != "pii.email" || response.Results[0].Finding.Location.Path != "/test-input" {
		t.Fatalf("response=%+v", response)
	}
	if decision := response.Results[0].Decision; decision.Action != domain.ActionRedact || decision.Source != "default" || decision.MatchedScope != nil || decision.Reason != "default policy" {
		t.Fatalf("decision=%+v", decision)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"safe","unexpected":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder = httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", recorder.Code)
	}
}

func TestFalsePositiveFeedbackPersistsOnlyDetectionMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "feedback.json")
	store, err := feedback.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithFeedbackStore(store); err != nil {
		t.Fatal(err)
	}
	finding := domain.Finding{RuleID: "pii.email", Category: "pii.email", Detector: "regex", Severity: domain.SeverityHigh, Confidence: 1, SuggestedAction: domain.ActionRedact, Location: domain.ContentLocation{Path: "/test-input", Start: 8, End: 27}}
	payload, _ := json.Marshal(map[string]any{
		"finding":        finding,
		"policy_action":  domain.ActionAsk,
		"policy_context": policy.Scope{AgentID: "agent-a", FindingType: "pii.email"},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/feedback/false-positives", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.reportFalsePositive(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	entries, err := store.Recent()
	if err != nil || len(entries) != 1 || entries[0].RuleID != "pii.email" || entries[0].PolicyAction != domain.ActionAsk || entries[0].Scope.AgentID != "agent-a" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "private@example.com") {
		t.Fatal("feedback store retained sensitive input")
	}
}

func TestFalsePositiveFeedbackRejectsUntrustedOrUnavailableReports(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.reportFalsePositive(recorder, httptest.NewRequest(http.MethodPost, "/v1/feedback/false-positives", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable store status=%d", recorder.Code)
	}
	store, err := feedback.NewStore(filepath.Join(t.TempDir(), "private", "feedback.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithFeedbackStore(store); err != nil {
		t.Fatal(err)
	}
	invalid := `{"finding":{"rule_id":"pii.email","category":"pii.email","severity":"high","location":{"path":"/test-input","start":0,"end":1},"confidence":1,"detector":"regex","suggested_action":"redact"},"policy_action":"redact","policy_context":{"finding_type":"pii.email"},"text":"private@example.com"}`
	recorder = httptest.NewRecorder()
	s.reportFalsePositive(recorder, httptest.NewRequest(http.MethodPost, "/v1/feedback/false-positives", strings.NewReader(invalid)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("untrusted report status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if entries, err := store.Recent(); err != nil || len(entries) != 0 {
		t.Fatalf("rejected feedback was retained: entries=%+v err=%v", entries, err)
	}
}
