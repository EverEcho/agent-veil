package proxy

import (
	"bufio"
	"encoding/json"
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

func TestLegacyMCPSSEDualEndpointRoundTripProtectsProviderBoundary(t *testing.T) {
	providerResponse := make(chan string, 1)
	var providerRequest string
	var providerCapabilityHeaders []string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "event: endpoint\ndata: /messages?provider_session=exact\n\n")
			w.(http.Flusher).Flush()
			response := <-providerResponse
			_, _ = io.WriteString(w, "event: message\ndata: "+response+"\n\n")
		case "/messages":
			payload, _ := io.ReadAll(request.Body)
			providerRequest = string(payload)
			providerCapabilityHeaders = append(providerCapabilityHeaders, request.Header.Get(HeaderSession), request.Header.Get(HeaderRouteToken))
			if request.URL.RawQuery != "provider_session=exact" {
				t.Errorf("dynamic Provider query=%q", request.URL.RawQuery)
			}
			var envelope map[string]any
			if err := json.Unmarshal(payload, &envelope); err != nil {
				t.Errorf("Provider request JSON: %v", err)
			}
			arguments := envelope["params"].(map[string]any)["arguments"].(map[string]any)
			response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"email": arguments["email"]}})
			providerResponse <- string(response)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected Provider path %q", request.URL.Path)
			http.NotFound(w, request)
		}
	}))
	defer provider.Close()

	manager := session.NewManager()
	legacy := NewDefaultLegacySSEManager()
	upstream, _ := url.Parse(provider.URL + "/sse")
	handler, err := NewHandler(manager, []Route{{ID: "legacy", Protocol: domain.ProtocolMCPLegacySSE, Upstream: upstream, LegacySessions: legacy, CapabilityPath: true, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 16, MaxOriginalBytes: 1024}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()
	created, err := manager.Create("", proxyServer.URL, []string{"legacy"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	streamRequest, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/route/legacy/mcp", nil)
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamRequest.Header.Set(HeaderSession, created.Session.ID)
	streamRequest.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	streamResponse, err := http.DefaultClient.Do(streamRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer streamResponse.Body.Close()
	reader := bufio.NewReader(streamResponse.Body)
	var endpointEvent strings.Builder
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read rewritten endpoint: %v", readErr)
		}
		endpointEvent.WriteString(line)
		if line == "\n" {
			break
		}
	}
	endpointLine := ""
	for _, line := range strings.Split(endpointEvent.String(), "\n") {
		if strings.HasPrefix(line, "data: ") {
			endpointLine = strings.TrimPrefix(line, "data: ")
		}
	}
	if streamResponse.StatusCode != http.StatusOK || !strings.HasPrefix(endpointLine, proxyServer.URL+"/route/legacy/__veil/") || strings.Contains(endpointLine, provider.URL) {
		t.Fatalf("status=%d endpoint event=%q", streamResponse.StatusCode, endpointEvent.String())
	}
	mismatched, _ := http.NewRequest(http.MethodPost, endpointLine, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	mismatched.Header.Set("Content-Type", "application/json")
	mismatched.Header.Set(HeaderSession, created.Session.ID)
	mismatched.Header.Set(HeaderRouteToken, strings.Repeat("0", 64))
	mismatchedResponse, err := http.DefaultClient.Do(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	_ = mismatchedResponse.Body.Close()
	if mismatchedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mismatched redundant capability status=%d", mismatchedResponse.StatusCode)
	}
	postRequest, _ := http.NewRequest(http.MethodPost, endpointLine, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"email":"dev@example.com"}}}`))
	postRequest.Header.Set("Content-Type", "application/json")
	postRequest.Header.Set(HeaderSession, created.Session.ID)
	postRequest.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	postResponse, err := http.DefaultClient.Do(postRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, postResponse.Body)
	_ = postResponse.Body.Close()
	streamTail, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if postResponse.StatusCode != http.StatusAccepted || strings.Contains(providerRequest, "dev@example.com") || !strings.Contains(providerRequest, "[[VEIL_") || !strings.Contains(string(streamTail), "dev@example.com") || len(providerCapabilityHeaders) != 2 || providerCapabilityHeaders[0] != "" || providerCapabilityHeaders[1] != "" || legacy.Len() != 0 {
		t.Fatalf("post=%d provider=%s headers=%v stream=%s channels=%d", postResponse.StatusCode, providerRequest, providerCapabilityHeaders, streamTail, legacy.Len())
	}
}

func TestLegacyMCPSSERejectsCrossOriginAdvertisedEndpoint(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: endpoint\ndata: https://attacker.example/messages\n\n")
	}))
	defer provider.Close()
	manager := session.NewManager()
	legacy := NewDefaultLegacySSEManager()
	upstream, _ := url.Parse(provider.URL + "/sse")
	handler, err := NewHandler(manager, []Route{{ID: "legacy", Protocol: domain.ProtocolMCPLegacySSE, Upstream: upstream, LegacySessions: legacy, Policy: policy.Engine{Default: domain.ActionRedact}, MaxRequestBytes: 4096, MaxResponseBytes: 4096, VaultLimits: redactor.Limits{MaxEntries: 16, MaxOriginalBytes: 1024}}}, provider.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()
	created, _ := manager.Create("", proxyServer.URL, []string{"legacy"}, time.Minute)
	request, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/route/legacy/mcp", nil)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set(HeaderSession, created.Session.ID)
	request.Header.Set(HeaderRouteToken, created.Routes[0].Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), string(domain.ErrUpstreamDenied)) || legacy.Len() != 0 {
		t.Fatalf("status=%d body=%s channels=%d", response.StatusCode, body, legacy.Len())
	}
}
