package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		midpoint := len(payload) / 2
		_, _ = w.Write([]byte("data: " + string(payload[:midpoint])))
		w.(http.Flusher).Flush()
		_, _ = w.Write(append(payload[midpoint:], []byte("\n\n")...))
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
