package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	veilauth "github.com/agentveil/agentveil/internal/auth"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
	"github.com/agentveil/agentveil/internal/session"
)

func TestEndToEndProviderOnlyReceivesRedactedContent(t *testing.T) {
	var providerBody string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		providerBody = string(payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, err := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()
	request, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/route/primary/v1/responses", strings.NewReader(`{"input":"email dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || strings.Contains(providerBody, "dev@example.com") || !strings.Contains(string(result), "dev@example.com") {
		t.Fatalf("status=%d provider=%s client=%s", response.StatusCode, providerBody, result)
	}
}

type finalBodySigner struct{ sawOriginal bool }

func (s *finalBodySigner) Apply(request *http.Request) error {
	body, _ := io.ReadAll(request.Body)
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	s.sawOriginal = strings.Contains(string(body), "dev@example.com")
	request.Header.Set("X-Signed", "yes")
	return nil
}
func TestAuthenticationRunsAfterRedaction(t *testing.T) {
	signer := &finalBodySigner{}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Signed") != "yes" {
			t.Error("signature missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"ok"}`))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Auth: domain.AuthStrategy{Type: domain.AuthCustom}, AuthApplier: veilauth.Applier{Signers: map[domain.AuthType]veilauth.Signer{domain.AuthCustom: signer}}, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if signer.sawOriginal || recorder.Code != http.StatusOK {
		t.Fatalf("original=%v status=%d", signer.sawOriginal, recorder.Code)
	}
}

func TestMissingRouteCapabilityIsRejectedBeforeForward(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerCalls++ }))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	handler, _ := NewHandler(session.NewManager(), []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 10, MaxResponseBytes: 10, VaultLimits: redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 10}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || providerCalls != 0 {
		t.Fatalf("status=%d calls=%d", recorder.Code, providerCalls)
	}
}

func TestStreamingResponseRestoresPlaceholder(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		var requestBody map[string]any
		_ = json.Unmarshal(payload, &requestBody)
		event, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": requestBody["input"]})
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		midpoint := len(event) / 2
		_, _ = w.Write([]byte("data: " + string(event[:midpoint])))
		w.(http.Flusher).Flush()
		_, _ = w.Write(append(event[midpoint:], []byte("\n\n")...))
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 8192, VaultLimits: redactor.Limits{MaxEntries: 10, MaxOriginalBytes: 1024}}}, provider.Client())
	server := httptest.NewServer(handler)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/route/primary/v1/responses", strings.NewReader(`{"input":"dev@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "dev@example.com") {
		t.Fatalf("stream did not restore placeholder: %s", body)
	}
}

func TestRedirectCannotEscapeCurrentRoute(t *testing.T) {
	evilCalls := 0
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilCalls++ }))
	defer evil.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer provider.Close()
	upstream, _ := url.Parse(provider.URL)
	manager := session.NewManager()
	created, _ := manager.Create("", "local", []string{"primary"}, time.Minute)
	handler, _ := NewHandler(manager, []Route{{ID: "primary", Upstream: upstream, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 1024, MaxResponseBytes: 1024, VaultLimits: redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100}}}, provider.Client())
	request := httptest.NewRequest(http.MethodPost, "/route/primary/v1/responses", strings.NewReader(`{"input":"safe"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if evilCalls != 0 || recorder.Code != http.StatusBadGateway {
		t.Fatalf("redirect escaped: calls=%d status=%d", evilCalls, recorder.Code)
	}
}
