package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/rulestore"
)

func TestWriteCompatibilityReportUsesAuthenticatedVersionedCoreAPI(t *testing.T) {
	token := "01234567890123456789012345678901"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/compatibility" || request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion {
			t.Fatalf("request path=%q headers=%v", request.URL.Path, request.Header)
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"agent":"codex","version":"0.153.4","platform":"linux","mode":"launch","surface":"model_primary","protocol":"openai_responses","auth":"passthrough","coverage":"protected","verification":"launch_smoke","notes":"verified"}]`)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := writeCompatibilityReport(&output, server.URL, token); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"surface": "model_primary"`) || !strings.Contains(output.String(), `"verification": "launch_smoke"`) {
		t.Fatalf("compatibility output=%s", output.String())
	}
	if err := writeCompatibilityReport(nil, server.URL, token); err == nil {
		t.Fatal("nil compatibility writer was accepted")
	}
}

func TestOfflineCompatibilityReportUsesTheValidatedBuildMatrix(t *testing.T) {
	var output bytes.Buffer
	if err := writeOfflineCompatibilityReport(&output); err != nil {
		t.Fatal(err)
	}
	var records []compatibility.Record
	if err := json.Unmarshal(output.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != len(compatibility.Current()) || len(records) == 0 {
		t.Fatalf("records=%d current=%d", len(records), len(compatibility.Current()))
	}
	for _, record := range records {
		if record.Coverage == domain.CoverageProtected && (record.Surface == domain.SurfaceUnknown || record.Protocol == domain.ProtocolUnknown || record.Verification != compatibility.VerificationLaunchSmoke) {
			t.Fatalf("offline release report overstated coverage: %+v", record)
		}
	}
	if err := writeOfflineCompatibilityReport(nil); err == nil {
		t.Fatal("nil offline compatibility writer was accepted")
	}
}

func TestCoreStatusExplainsAuditAndSemanticDegradation(t *testing.T) {
	const token = "01234567890123456789012345678901"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"degraded","api_version":"v1","audit":"error","audit_failures":"3","semantic":"required_unavailable"}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := writeCoreStatus(&output, server.URL, token); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"AgentVeil Core: degraded (API v1)", "Audit: error (3 failures)", "Semantic: required_unavailable"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("status output=%s", output.String())
		}
	}
}

func TestCoreStatusRejectsInvalidOrInconsistentHealth(t *testing.T) {
	for _, payload := range []string{
		`{"status":"healthy","api_version":"v1","audit":"ok","semantic":"active"}`,
		`{"status":"degraded","api_version":"v1","audit":"error","semantic":"disabled"}`,
		`{"status":"ok","api_version":"v1","audit":"ok","audit_failures":"1","semantic":"disabled"}`,
		`{"status":"degraded","api_version":"v1","audit":"error","audit_failures":"zero","semantic":"required_unavailable"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(core.APIVersionHeader, core.APIVersion)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, payload)
		}))
		if err := writeCoreStatus(io.Discard, server.URL, "token"); err == nil {
			server.Close()
			t.Fatalf("invalid health accepted: %s", payload)
		}
		server.Close()
	}
	if err := writeCoreStatus(nil, "http://127.0.0.1:1", "token"); err == nil {
		t.Fatal("nil status writer was accepted")
	}
}

func TestAuditReportRevalidatesPrivacySafeMetadata(t *testing.T) {
	const token = "01234567890123456789012345678901"
	event := domain.AuditEvent{Timestamp: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC), SessionID: "session-1", AgentID: "codex", SurfaceID: "primary", Protocol: domain.ProtocolOpenAIResponses, FindingTypes: []string{"pii.email"}, FindingCount: 1, Severity: domain.SeverityHigh, Action: domain.ActionRedact, LatencyMS: 4, WorkspaceRef: "sha256:0123456789abcdef0123456789abcdef"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode([]domain.AuditEvent{event}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := writeAuditReport(&output, server.URL, token); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"workspace_ref": "sha256:0123456789abcdef0123456789abcdef"`) || strings.Contains(output.String(), "/private/") {
		t.Fatalf("audit output=%s", output.String())
	}
}

func TestAuditReportRejectsUnsafeCoreEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"timestamp":"2026-01-02T03:04:05Z","finding_count":0,"action":"block","latency_ms":0,"workspace_ref":"/private/customer"}]`)
	}))
	defer server.Close()
	if err := writeAuditReport(io.Discard, server.URL, "token"); err == nil || !strings.Contains(err.Error(), "invalid audit event") {
		t.Fatalf("unsafe audit event error=%v", err)
	}
	if err := writeAuditReport(nil, "http://127.0.0.1:1", "token"); err == nil {
		t.Fatal("nil audit writer was accepted")
	}
}

func TestRulesCommandRejectsUnsafeFilesAndArguments(t *testing.T) {
	if err := executeRulesCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", []string{"future"}); err == nil {
		t.Fatal("unknown rule command was accepted")
	}
	if err := executeRulesCommand(context.Background(), io.Discard, "https://example.com", "token", []string{"list"}); err == nil {
		t.Fatal("non-loopback rule management endpoint was accepted")
	}
	if err := executeRulesCommand(nil, io.Discard, "http://127.0.0.1:1", "token", []string{"list"}); err == nil {
		t.Fatal("nil context was accepted")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "link.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err == nil {
		if _, err := readCLIFile(link, 1024); err == nil {
			t.Fatal("symlinked CLI file was accepted")
		}
	}
	var manifest rulestore.Manifest
	if err := decodeStrictJSON([]byte(`{"schema_version":"v1","version":"one","version":"two"}`), &manifest); err == nil {
		t.Fatal("ambiguous manifest JSON was accepted")
	}
}

func TestModelsCommandRejectsUnsafeInputs(t *testing.T) {
	if err := executeModelsCommand(context.Background(), io.Discard, "https://example.com", "token", []string{"list"}); err == nil {
		t.Fatal("non-loopback model management endpoint was accepted")
	}
	if err := managementJSONWithTimeout(nil, http.MethodGet, "http://127.0.0.1:1/v1/models", "token", nil, nil, time.Second); err == nil {
		t.Fatal("nil management context was accepted")
	}
	if err := managementJSONWithTimeout(context.Background(), http.MethodGet, "http://127.0.0.1:1/v1/models", "token", nil, nil, 0); err == nil {
		t.Fatal("zero management timeout was accepted")
	}
	redirectFollowed := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectFollowed = true }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if err := executeModelsCommand(context.Background(), io.Discard, redirect.URL, "token", []string{"list"}); err == nil {
		t.Fatal("redirecting model management response was accepted")
	}
	if redirectFollowed {
		t.Fatal("management client followed a redirect")
	}
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	artifactPath := filepath.Join(directory, "model.bin")
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: 2, SHA256: strings.Repeat("0", 64), Signature: "AA=="}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestPayload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("oversized"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := executeModelsCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", []string{"install", manifestPath, artifactPath}); err == nil || !strings.Contains(err.Error(), "size does not match") {
		t.Fatalf("mismatched model size error=%v", err)
	}
}

func TestPolicyCommandGetsAndAppliesValidatedDocuments(t *testing.T) {
	const token = "01234567890123456789012345678901"
	document := policy.Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: []policy.Rule{{Scope: policy.Scope{FindingType: "secret.private_key"}, Action: domain.ActionBlock}}}
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		methods = append(methods, request.Method)
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(document); err != nil {
				t.Fatal(err)
			}
			return
		}
		var applied policy.Document
		if request.Header.Get("Content-Type") != "application/json" || json.NewDecoder(request.Body).Decode(&applied) != nil || applied.SchemaVersion != "v1" || len(applied.Rules) != 1 {
			t.Fatalf("applied policy=%+v", applied)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.json")
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := executePolicyCommand(context.Background(), &output, server.URL, token, []string{"get"}); err != nil {
		t.Fatal(err)
	}
	if err := executePolicyCommand(context.Background(), io.Discard, server.URL, token, []string{"apply", path}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"default": "redact"`) || !slices.Equal(methods, []string{http.MethodGet, http.MethodPut}) {
		t.Fatalf("output=%s methods=%v", output.String(), methods)
	}
}

func TestPolicyCommandRejectsInvalidDocumentsBeforeUpload(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.json")
	payload := []byte(`{"schema_version":"v1","default":"REDACT","rules":[{"scope":{"finding_type":"secret.private_key"},"action":"BLOCK"},{"scope":{"finding_type":"secret.private_key"},"action":"ALLOW"}]}`)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := executePolicyCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", []string{"apply", path}); err == nil || !strings.Contains(err.Error(), "validate policy document") {
		t.Fatalf("duplicate policy scopes error=%v", err)
	}
	if err := executePolicyCommand(context.Background(), io.Discard, "https://example.com", "token", []string{"get"}); err == nil {
		t.Fatal("non-loopback policy endpoint was accepted")
	}
}

func TestApprovalsCommandListsMetadataAndResolvesOnce(t *testing.T) {
	const token = "01234567890123456789012345678901"
	const approvalID = "0123456789abcdef0123456789abcdef"
	approval := policy.Approval{ID: approvalID, Finding: domain.Finding{RuleID: "pii.email", Category: "pii.email", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: "/input", Start: 4, End: 8}, Confidence: 0.99, Detector: "regex", SuggestedAction: domain.ActionRedact}}
	var resolved domain.Action
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]policy.Approval{approval}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if request.Method != http.MethodPost || request.URL.EscapedPath() != "/v1/approvals/"+approvalID {
			t.Fatalf("request=%s %s", request.Method, request.URL.EscapedPath())
		}
		var body map[string]domain.Action
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		resolved = body["action"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := executeApprovalsCommand(context.Background(), &output, server.URL, token, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := executeApprovalsCommand(context.Background(), io.Discard, server.URL, token, []string{"resolve", approvalID, "redact"}); err != nil {
		t.Fatal(err)
	}
	if resolved != domain.ActionRedact || !strings.Contains(output.String(), `"category": "pii.email"`) || strings.Contains(output.String(), "original") {
		t.Fatalf("resolved=%q output=%s", resolved, output.String())
	}
}

func TestApprovalsCommandRejectsUntrustedIdentifiersAndActions(t *testing.T) {
	for _, args := range [][]string{{"resolve", "../policy", "allow"}, {"resolve", "0123456789abcdef0123456789abcdef", "ask"}, {"resolve", "0123456789ABCDEF0123456789ABCDEF", "block"}} {
		if err := executeApprovalsCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", args); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args=%v error=%v", args, err)
		}
	}
	if validApprovalID("0123456789abcdef0123456789abcdeg") {
		t.Fatal("non-hex approval identifier was accepted")
	}
}

func TestLiveStateCommandsRejectInvalidInputsAndCallTrees(t *testing.T) {
	if err := writeLiveState(nil, io.Discard, "http://127.0.0.1:1", "token", "agents"); err == nil {
		t.Fatal("nil live state context was accepted")
	}
	if err := writeLiveState(context.Background(), nil, "http://127.0.0.1:1", "token", "agents"); err == nil {
		t.Fatal("nil live state writer was accepted")
	}
	if err := writeLiveState(context.Background(), io.Discard, "https://example.com", "token", "agents"); err == nil {
		t.Fatal("non-loopback live state endpoint was accepted")
	}
	if err := writeLiveState(context.Background(), io.Discard, "http://127.0.0.1:1", "token", "unknown"); err == nil {
		t.Fatal("unknown live state resource was accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"wrong-parent":[{"session_id":"child","parent_session_id":"parent","expires_at":"2026-01-02T04:04:05Z","surfaces":[{"route_id":"route-primary","coverage":"protected"}]}]}`)
	}))
	defer server.Close()
	if err := writeLiveState(context.Background(), io.Discard, server.URL, "token", "calls"); err == nil || !strings.Contains(err.Error(), "invalid call tree") {
		t.Fatalf("invalid call tree error=%v", err)
	}
}

func TestSessionsCommandListsAndRevokesAnExactSession(t *testing.T) {
	const token = "01234567890123456789012345678901"
	const sessionID = "session-0123456789abcdef0123456789abcdef"
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		methods = append(methods, request.Method+" "+request.URL.EscapedPath())
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"id":"`+sessionID+`","core_endpoint":"http://127.0.0.1:1","started_at":"2026-01-02T03:04:05Z","expires_at":"2026-01-02T04:04:05Z","route_ids":["route-primary"]}]`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := executeSessionsCommand(context.Background(), &output, server.URL, token, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := executeSessionsCommand(context.Background(), io.Discard, server.URL, token, []string{"revoke", sessionID}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), sessionID) || !slices.Equal(methods, []string{"GET /v1/sessions", "DELETE /v1/sessions/" + sessionID}) {
		t.Fatalf("methods=%v output=%s", methods, output.String())
	}
}

func TestSessionsCommandRejectsUnsafeIdentifiersAndArguments(t *testing.T) {
	for _, args := range [][]string{{"revoke"}, {"revoke", "../agents"}, {"revoke", "session-0123456789ABCDEF0123456789ABCDEF"}, {"remove", "session-0123456789abcdef0123456789abcdef"}} {
		if err := executeSessionsCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", args); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args=%v error=%v", args, err)
		}
	}
	if validSessionID("session-0123456789abcdef0123456789abcdeg") {
		t.Fatal("non-hex session identifier was accepted")
	}
}

func TestAgentsCommandListsAndRemovesAnExactGeneration(t *testing.T) {
	const token = "01234567890123456789012345678901"
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		methods = append(methods, request.Method+" "+request.URL.RequestURI())
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"manifest":{"agent":{"id":"codex-local"}},"state":"active","generation":7}]`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := executeAgentsCommand(context.Background(), &output, server.URL, token, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := executeAgentsCommand(context.Background(), io.Discard, server.URL, token, []string{"remove", "codex-local", "--generation", "7"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"generation": 7`) || !slices.Equal(methods, []string{"GET /v1/agents", "DELETE /v1/agents/codex-local?generation=7"}) {
		t.Fatalf("methods=%v output=%s", methods, output.String())
	}
}

func TestAgentsCommandRejectsBroadRemovalAndUnsafeTargets(t *testing.T) {
	for _, args := range [][]string{{"remove", "codex-local"}, {"remove", "../sessions", "--generation", "7"}, {"remove", "-agent", "--generation", "7"}, {"remove", "agent", "--generation", "0"}, {"remove", "agent", "--generation", "01"}, {"delete", "agent", "--generation", "7"}} {
		if err := executeAgentsCommand(context.Background(), io.Discard, "http://127.0.0.1:1", "token", args); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args=%v error=%v", args, err)
		}
	}
	for _, id := range []string{"agent", "agent.one", "agent_two", "Agent-3"} {
		if !validResourceID(id) {
			t.Fatalf("valid resource ID rejected: %q", id)
		}
	}
}
