package main

import (
	"bytes"
	"context"
	"encoding/base64"
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

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
)

func TestWebCommandPrintsOrOpensVerifiedCoreEndpoint(t *testing.T) {
	server, err := core.New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	t.Setenv("VEIL_CORE_ENDPOINT", server.Endpoint())
	t.Setenv("VEIL_ADMIN_TOKEN", "01234567890123456789012345678901")
	var output bytes.Buffer
	opened := ""
	if err := webCommand(nil, &output, func(target string) error { opened = target; return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(opened, server.Endpoint()+"/#ticket=") || strings.TrimSpace(output.String()) != opened {
		t.Fatalf("opened=%q output=%q", opened, output.String())
	}
	output.Reset()
	opened = ""
	if err := webCommand([]string{"--print"}, &output, func(target string) error { opened = target; return nil }); err != nil {
		t.Fatal(err)
	}
	if opened != "" || !strings.HasPrefix(strings.TrimSpace(output.String()), server.Endpoint()+"/#ticket=") {
		t.Fatalf("print mode opened=%q output=%q", opened, output.String())
	}
	if err := webCommand([]string{"--unknown"}, &output, func(string) error { return nil }); err == nil {
		t.Fatal("invalid web arguments were accepted")
	}
}

func TestResolveCoreEndpointUsesExplicitValueOrSecureState(t *testing.T) {
	if got, err := resolveCoreEndpoint("http://127.0.0.1:1234"); err != nil || got != "http://127.0.0.1:1234" {
		t.Fatalf("explicit endpoint=%q err=%v", got, err)
	}
	configDirectory := useTestUserConfigDir(t)
	path := filepath.Join(configDirectory, "agentveil", "core.json")
	server, err := core.New(session.NewManager(), "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	if err := instance.WriteState(path, instance.State{SchemaVersion: "v1", APIEndpoint: server.Endpoint(), InstanceID: server.InstanceID(), ProcessID: 7, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveCoreEndpoint(""); err != nil || got != server.Endpoint() {
		t.Fatalf("discovered endpoint=%q err=%v", got, err)
	}
}

func TestResolveCoreEndpointRejectsStaleIdentityWithoutSendingAdminToken(t *testing.T) {
	requestAuthorization := "not-called"
	stale := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestAuthorization = request.Header.Get("Authorization")
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"api_version":"v1","instance_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	}))
	defer stale.Close()
	configDirectory := useTestUserConfigDir(t)
	path := filepath.Join(configDirectory, "agentveil", "core.json")
	instanceID := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := instance.WriteState(path, instance.State{SchemaVersion: "v1", APIEndpoint: stale.URL, InstanceID: instanceID, ProcessID: 7, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCoreEndpoint(""); err == nil {
		t.Fatal("stale Core identity was trusted")
	}
	if requestAuthorization != "" {
		t.Fatalf("identity preflight disclosed authorization %q", requestAuthorization)
	}
}

func TestManagementJSONRejectsUnboundedOrAmbiguousResponses(t *testing.T) {
	tests := []struct {
		name    string
		headers func(http.Header)
		body    string
	}{
		{name: "missing content type", body: `{}`},
		{name: "missing API version", headers: func(header http.Header) {
			header.Del(core.APIVersionHeader)
			header.Set("Content-Type", "application/json")
		}, body: `{}`},
		{name: "incompatible API version", headers: func(header http.Header) {
			header.Set(core.APIVersionHeader, "v2")
			header.Set("Content-Type", "application/json")
		}, body: `{}`},
		{name: "duplicate content type", headers: func(header http.Header) {
			header.Add("Content-Type", "application/json")
			header.Add("Content-Type", "application/json")
		}, body: `{}`},
		{name: "unsupported encoding", headers: func(header http.Header) {
			header.Set("Content-Type", "application/json")
			header.Set("Content-Encoding", "br")
		}, body: `{}`},
		{name: "ambiguous JSON", headers: func(header http.Header) {
			header.Set("Content-Type", "application/json")
		}, body: `{"status":"ok","status":"forged"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(core.APIVersionHeader, core.APIVersion)
				if test.headers != nil {
					test.headers(w.Header())
				}
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			var output map[string]string
			if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err == nil {
				t.Fatal("unsafe management response was accepted")
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, maxManagementResponseBytes+1))
	}))
	defer server.Close()
	var output map[string]string
	if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err == nil {
		t.Fatal("oversized management response was accepted")
	}
}

func TestManagementJSONDecodesStrictBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	var output struct {
		Status string `json:"status"`
	}
	if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err != nil || output.Status != "ok" {
		t.Fatalf("output=%+v error=%v", output, err)
	}
}

func TestManagementJSONSanitizesErrorResponses(t *testing.T) {
	for name, body := range map[string]string{
		"valid":   `{"error":"INVALID_SESSION"}`,
		"control": "{\"error\":\"BAD\\u001b[31m\"}",
		"unknown": `{"error":"INVALID_SESSION","detail":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(core.APIVersionHeader, core.APIVersion)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			err := managementJSON(context.Background(), http.MethodPost, server.URL, "01234567890123456789012345678901", nil, nil)
			if err == nil {
				t.Fatal("management error response was accepted")
			}
			message := err.Error()
			if strings.Contains(message, "\x1b") || name == "valid" && !strings.Contains(message, "INVALID_SESSION") || name != "valid" && strings.Contains(message, "secret") {
				t.Fatalf("unsafe or missing error message=%q", message)
			}
		})
	}
}

func TestManagementJSONRequestsIdentityEncoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding=%q", request.Header.Get("Accept-Encoding"))
		}
		if request.Header.Get(core.APIVersionHeader) != core.APIVersion {
			t.Errorf("management API version=%q", request.Header.Get(core.APIVersionHeader))
		}
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	var output map[string]string
	if err := managementJSON(context.Background(), http.MethodGet, server.URL, "01234567890123456789012345678901", nil, &output); err != nil {
		t.Fatal(err)
	}
}

func TestRulesCommandUsesAuthenticatedVersionedManagementAPI(t *testing.T) {
	const token = "01234567890123456789012345678901"
	type requestRecord struct{ method, path string }
	var requests []requestRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		requests = append(requests, requestRecord{request.Method, request.URL.EscapedPath()})
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		if request.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"active":"1.0.0","versions":[{"schema_version":"v1","version":"1.0.0","size":2,"sha256":"00","signature":"AA=="}]}`)
			return
		}
		if request.Method == http.MethodPost {
			var input struct {
				Manifest       rulestore.Manifest `json:"manifest"`
				ArtifactBase64 string             `json:"artifact_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Manifest.Version != "2.0.0" || input.ArtifactBase64 != base64.StdEncoding.EncodeToString([]byte("{}")) {
				t.Fatalf("install input=%+v err=%v", input, err)
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	artifactPath := filepath.Join(directory, "rules.json")
	if err := os.WriteFile(manifestPath, []byte(`{"schema_version":"v1","version":"2.0.0","size":2,"sha256":"00","signature":"AA=="}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	for _, args := range [][]string{{"list"}, {"install", manifestPath, artifactPath}, {"activate", "2.0.0"}, {"deactivate"}, {"remove", "2.0.0"}} {
		if err := executeRulesCommand(context.Background(), &output, server.URL, token, args); err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	if !strings.Contains(output.String(), `"active": "1.0.0"`) {
		t.Fatalf("list output=%s", output.String())
	}
	want := []requestRecord{{http.MethodGet, "/v1/rules"}, {http.MethodPost, "/v1/rules"}, {http.MethodPut, "/v1/rules/active"}, {http.MethodDelete, "/v1/rules/active"}, {http.MethodDelete, "/v1/rules/2.0.0"}}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests=%+v want=%+v", requests, want)
	}
}

func TestModelsCommandStreamsAuthenticatedVersionedManagementAPI(t *testing.T) {
	const token = "01234567890123456789012345678901"
	type requestRecord struct{ method, path string }
	var requests []requestRecord
	artifactPayload := []byte("model-bytes")
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "2.0.0", Size: int64(len(artifactPayload)), SHA256: strings.Repeat("0", 64), Signature: "AA=="}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("headers=%v", request.Header)
		}
		requests = append(requests, requestRecord{request.Method, request.URL.EscapedPath()})
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		switch {
		case request.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"versions":[],"runtime":{"connected":false,"required":false,"active":false,"resource_state":"inactive"}}`)
		case request.Method == http.MethodPost:
			decodedManifest, decodeErr := base64.StdEncoding.DecodeString(request.Header.Get(core.ModelManifestHeader))
			body, readErr := io.ReadAll(request.Body)
			if request.Header.Get("Content-Type") != "application/octet-stream" || request.ContentLength != manifest.Size || decodeErr != nil || !bytes.Equal(decodedManifest, manifestPayload) || readErr != nil || !bytes.Equal(body, artifactPayload) {
				t.Fatalf("model upload content_type=%q length=%d manifest=%s body=%q decode_err=%v read_err=%v", request.Header.Get("Content-Type"), request.ContentLength, decodedManifest, body, decodeErr, readErr)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(manifestPayload)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	artifactPath := filepath.Join(directory, "model.bin")
	if err := os.WriteFile(manifestPath, manifestPayload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, artifactPayload, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	for _, args := range [][]string{{"list"}, {"install", manifestPath, artifactPath}, {"activate", "2.0.0"}, {"deactivate"}, {"remove", "2.0.0"}} {
		if err := executeModelsCommand(context.Background(), &output, server.URL, token, args); err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	if !strings.Contains(output.String(), `"resource_state": "inactive"`) {
		t.Fatalf("list output=%s", output.String())
	}
	want := []requestRecord{{http.MethodGet, "/v1/models"}, {http.MethodPost, "/v1/models"}, {http.MethodPut, "/v1/models/active"}, {http.MethodDelete, "/v1/models/active"}, {http.MethodDelete, "/v1/models/2.0.0"}}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests=%+v want=%+v", requests, want)
	}
}

func TestLiveStateCommandsUseAuthenticatedVersionedManagementAPI(t *testing.T) {
	const token = "01234567890123456789012345678901"
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(core.APIVersionHeader) != core.APIVersion || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		paths = append(paths, request.URL.Path)
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/agents":
			_, _ = io.WriteString(w, `[{"state":"active","generation":1}]`)
		case "/v1/sessions":
			_, _ = io.WriteString(w, `[{"id":"session-parent","core_endpoint":"http://127.0.0.1:1","started_at":"2026-01-02T03:04:05Z","expires_at":"2026-01-02T04:04:05Z","route_ids":["route-primary"]}]`)
		case "/v1/call-tree":
			_, _ = io.WriteString(w, `{"parent":[{"session_id":"child","parent_session_id":"parent","interactive":false,"expires_at":"2026-01-02T04:04:05Z","surfaces":[{"route_id":"route-primary","coverage":"protected"}]}],"":[{"session_id":"parent","interactive":true,"expires_at":"2026-01-02T04:04:05Z","surfaces":[{"route_id":"route-primary","coverage":"protected"}]}]}`)
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	for _, resource := range []string{"agents", "sessions", "calls"} {
		if err := writeLiveState(context.Background(), &output, server.URL, token, resource); err != nil {
			t.Fatalf("resource=%s err=%v", resource, err)
		}
	}
	if !slices.Equal(paths, []string{"/v1/agents", "/v1/sessions", "/v1/call-tree"}) || !strings.Contains(output.String(), `"session_id": "child"`) {
		t.Fatalf("paths=%v output=%s", paths, output.String())
	}
}

func TestCompatibleCorePreflightRejectsMismatchedHealthVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(core.APIVersionHeader, core.APIVersion)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","api_version":"v2"}`)
	}))
	defer server.Close()
	if err := requireCompatibleCore(context.Background(), server.URL, "01234567890123456789012345678901"); err == nil {
		t.Fatal("mismatched health API version was accepted before protected launch")
	}
}

func TestManagementPayloadRejectsAmbiguousDiagnostics(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":"v1"}{"schema_version":"v1"}`,
		`{"schema_version":"v1","schema_version":"forged"}`,
	} {
		response := &http.Response{
			Header: http.Header{"Content-Type": {"application/json"}, core.APIVersionHeader: {core.APIVersion}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		if _, err := readManagementResponse(response, maxManagementResponseBytes); err == nil {
			t.Fatalf("ambiguous diagnostic payload was accepted: %s", body)
		}
	}
}
