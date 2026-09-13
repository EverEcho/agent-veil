package protocol

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestProtocolFixturesExtractOnlyBusinessContentAndRoundTrip(t *testing.T) {
	tests := []struct {
		endpoint, body string
		wantFields     int
		protected      string
	}{
		{"/v1/chat/completions", `{"messages":[{"role":"user","content":"secret"},{"role":"assistant","tool_calls":[{"function":{"name":"x","arguments":"{\"token\":\"secret\"}"}}]}],"model":"gpt"}`, 2, ""},
		{"/v1/responses", `{"instructions":"secret","input":[{"type":"function_call","arguments":"secret","signature":"do-not-scan"}],"model":"gpt"}`, 2, "do-not-scan"},
		{"/v1/messages", `{"system":"secret","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"do-not-scan","signature":"signed"},{"type":"tool_use","input":{"token":"secret"}}]}]}`, 2, "do-not-scan"},
		{"/v1beta/models/gemini-2.5-pro:generateContent", `{"systemInstruction":{"parts":[{"text":"secret"}]},"contents":[{"role":"user","parts":[{"text":"secret"},{"functionCall":{"name":"x","args":{"token":"secret"}}}]}]}`, 3, ""},
		{"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"token":"secret"}}}`, 2, ""},
	}
	for _, test := range tests {
		document, err := Parse(test.endpoint, "application/json; charset=utf-8", "", []byte(test.body))
		if err != nil {
			t.Fatalf("%s: %v", test.endpoint, err)
		}
		if len(document.Fields) != test.wantFields {
			t.Fatalf("%s fields=%+v", test.endpoint, document.Fields)
		}
		replacements := map[string]string{}
		for _, field := range document.Fields {
			replacements[field.Path] = "[[VEIL_TEST_0123456789ABCDEF]]"
		}
		result, err := document.Replace(replacements)
		if err != nil || !json.Valid(result) {
			t.Fatalf("round trip: %s %v", result, err)
		}
		if test.protected != "" && !contains(string(result), test.protected) {
			t.Fatalf("integrity field changed: %s", result)
		}
	}
}

func TestResolveMCPStreamableVersionAllowsOnlyImplementedRevisions(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
		ok     bool
	}{
		{name: "missing legacy fallback", want: MCPVersion20250326, ok: true},
		{name: "initial streamable HTTP", values: []string{MCPVersion20250326}, want: MCPVersion20250326, ok: true},
		{name: "June revision", values: []string{MCPVersion20250618}, want: MCPVersion20250618, ok: true},
		{name: "November revision", values: []string{MCPVersion20251125}, want: MCPVersion20251125, ok: true},
		{name: "new incompatible revision", values: []string{"2026-07-28"}},
		{name: "unknown revision", values: []string{"2099-01-01"}},
		{name: "empty revision", values: []string{""}},
		{name: "whitespace revision", values: []string{" 2025-11-25"}},
		{name: "combined revisions", values: []string{"2025-06-18, 2025-11-25"}},
		{name: "repeated revision", values: []string{MCPVersion20250618, MCPVersion20250618}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolveMCPStreamableVersion(test.values)
			if test.ok && (err != nil || got != test.want) {
				t.Fatalf("version=%q error=%v", got, err)
			}
			if !test.ok {
				var veilErr *domain.VeilError
				if !errors.As(err, &veilErr) || veilErr.Code != domain.ErrUnknownProtocol {
					t.Fatalf("version=%q error=%v", got, err)
				}
			}
		})
	}
}

func TestValidateMCPStreamableAccept(t *testing.T) {
	valid := []struct {
		method string
		values []string
	}{
		{http.MethodPost, []string{"application/json, text/event-stream"}},
		{http.MethodPost, []string{"application/json; q=0.5", "text/event-stream; q=1"}},
		{http.MethodGet, []string{"text/event-stream"}},
		{http.MethodDelete, nil},
	}
	for _, test := range valid {
		if err := ValidateMCPStreamableAccept(test.method, test.values); err != nil {
			t.Fatalf("method=%s values=%v error=%v", test.method, test.values, err)
		}
	}
	invalid := []struct {
		method string
		values []string
	}{
		{http.MethodPost, nil},
		{http.MethodPost, []string{"application/json"}},
		{http.MethodPost, []string{"application/json, text/event-stream; q=0"}},
		{http.MethodGet, []string{"application/json"}},
		{http.MethodGet, []string{"text/event-stream; q=bogus"}},
	}
	for _, test := range invalid {
		var veilErr *domain.VeilError
		err := ValidateMCPStreamableAccept(test.method, test.values)
		if !errors.As(err, &veilErr) || veilErr.Code != domain.ErrUnknownProtocol {
			t.Fatalf("method=%s values=%v error=%v", test.method, test.values, err)
		}
	}
}

func TestValidateMCPStreamableBodyVersionRejectsHeaderMismatch(t *testing.T) {
	matching := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`)
	if err := ValidateMCPStreamableBodyVersion(MCPVersion20251125, matching); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if err := ValidateMCPStreamableBodyVersion(MCPVersion20250326, legacy); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":1}}}`),
		[]byte(`not-json`),
	} {
		var veilErr *domain.VeilError
		err := ValidateMCPStreamableBodyVersion(MCPVersion20250326, body)
		if !errors.As(err, &veilErr) || veilErr.Code != domain.ErrUnknownProtocol {
			t.Fatalf("body=%s error=%v", body, err)
		}
	}
}

func TestUnknownProtocolAndCompressionFailClosed(t *testing.T) {
	for _, item := range []struct{ endpoint, contentType, encoding string }{{"/unknown", "application/json", ""}, {"/v1/responses", "text/plain", ""}, {"/v1/responses", "application/json; malformed", ""}, {"/v1/responses", "application/json", "gzip"}} {
		_, err := Parse(item.endpoint, item.contentType, item.encoding, []byte(`{}`))
		var veilErr *domain.VeilError
		if !errors.As(err, &veilErr) {
			t.Fatalf("expected fail-closed error for %+v", item)
		}
	}
}

func TestLegacyMCPSSECannotBorrowImplementedMCPAdapters(t *testing.T) {
	for _, operation := range []func() error{
		func() error {
			_, err := ParseExpected(domain.ProtocolMCPLegacySSE, "/mcp", "application/json", "", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			return err
		},
		func() error {
			_, err := ParseResponse(domain.ProtocolMCPLegacySSE, "application/json", []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return err
		},
		func() error {
			_, err := ParseStreamEvent(domain.ProtocolMCPLegacySSE, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return err
		},
	} {
		var veilErr *domain.VeilError
		if err := operation(); !errors.As(err, &veilErr) || veilErr.Code != domain.ErrUnknownProtocol {
			t.Fatalf("legacy SSE borrowed an implemented adapter: %v", err)
		}
	}
}

func TestMediaTypeRequiresExactValidRepresentation(t *testing.T) {
	for _, value := range []string{"application/json", "APPLICATION/JSON", "application/json; charset=utf-8"} {
		if !MediaTypeIs(value, "application/json") {
			t.Fatalf("valid media type rejected: %q", value)
		}
	}
	for _, value := range []string{"", "application/jsonish", "application/json; malformed", "application/json, text/plain", "text/event-streaming"} {
		if MediaTypeIs(value, "application/json") || MediaTypeIs(value, "text/event-stream") {
			t.Fatalf("invalid media type accepted: %q", value)
		}
	}
}

func TestProtocolEndpointsRejectTraversalAndAmbiguity(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"v1/responses",
		"/v1//responses",
		"/v1/../responses",
		"/v1/./responses",
		`/v1\responses`,
		"/" + strings.Repeat("x", MaxEndpointBytes),
	} {
		if _, err := ResolveEndpoint("", endpoint); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	if got, err := ResolveEndpoint(domain.ProtocolMCPStreamable, "/mcp"); err != nil || got != domain.ProtocolMCPStreamable {
		t.Fatalf("valid MCP endpoint rejected: protocol=%q error=%v", got, err)
	}
}

func TestContentProtectedProtocolsExcludeUnimplementedTransports(t *testing.T) {
	seen := map[domain.Protocol]struct{}{}
	for _, protocolType := range ContentProtectedProtocols() {
		if _, duplicate := seen[protocolType]; duplicate || !protocolType.Valid() || !SupportsContentProtection(protocolType) {
			t.Fatalf("invalid content-protected protocol registry: %q", protocolType)
		}
		seen[protocolType] = struct{}{}
	}
	for _, unsupported := range []domain.Protocol{domain.ProtocolMCPLegacySSE, domain.ProtocolLocalStdio, domain.ProtocolUnknown} {
		if SupportsContentProtection(unsupported) {
			t.Fatalf("unimplemented transport %q claims full content protection", unsupported)
		}
	}
}

func TestProtocolRejectsDuplicateKeysAcrossRequestAndResponse(t *testing.T) {
	if _, err := Parse("/v1/chat/completions", "application/json", "", []byte(`{"messages":[],"messages":[{"role":"user","content":"hidden"}]}`)); err == nil {
		t.Fatal("request with duplicate messages was accepted")
	}
	if _, err := ParseResponse(domain.ProtocolOpenAIChat, "application/json", []byte(`{"choices":[],"choices":[{"message":{"content":"hidden"}}]}`)); err == nil {
		t.Fatal("response with duplicate choices was accepted")
	}
	if _, err := ParseStreamEvent(domain.ProtocolOpenAIResponses, []byte(`{"type":"response.output_text.delta","delta":"safe","delta":"hidden"}`)); err == nil {
		t.Fatal("stream event with duplicate delta was accepted")
	}
}

func TestMalformedProtocolEnvelopesFailClosed(t *testing.T) {
	for _, test := range []struct {
		endpoint string
		body     string
	}{
		{"/v1/chat/completions", `{}`},
		{"/v1/chat/completions", `{"messages":"not-an-array"}`},
		{"/v1/responses", `{}`},
		{"/v1/messages", `[]`},
		{"/v1/messages", `{"messages":null}`},
		{"/v1beta/models/gemini-2.5-pro:generateContent", `{"contents":"unknown"}`},
		{"/mcp", `{"jsonrpc":"2.0","params":{}}`},
		{"/mcp", `[{"jsonrpc":"2.0","method":"tools/list"}]`},
		{"/mcp", `{"jsonrpc":"1.0","method":"tools/call","params":{}}`},
		{"/mcp", `{"jsonrpc":"2.0","method":"tools/call","params":[],"id":1}`},
		{"/mcp", `{"jsonrpc":"2.0","method":"tools/call","result":{},"id":1}`},
		{"/mcp", `{"jsonrpc":"2.0","method":"tools/call","id":null}`},
	} {
		if _, err := Parse(test.endpoint, "application/json", "", []byte(test.body)); err == nil {
			t.Fatalf("%s accepted malformed envelope %s", test.endpoint, test.body)
		}
	}
}

func TestMCPResponseAndStreamEnvelopesAreRoleSafe(t *testing.T) {
	invalidResponses := []string{
		`{"jsonrpc":"1.0","id":1,"result":{}}`,
		`{"jsonrpc":"2.0","result":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"bad"}}`,
		`{"jsonrpc":"2.0","id":1,"result":[]}`,
		`{"jsonrpc":"2.0","id":1,"error":"bad"}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-1.5,"message":"bad"}}`,
	}
	for _, body := range invalidResponses {
		if _, err := ParseResponse(domain.ProtocolMCPStreamable, "application/json", []byte(body)); err == nil {
			t.Fatalf("invalid MCP response accepted: %s", body)
		}
		if _, err := ParseStreamEvent(domain.ProtocolMCPStreamable, []byte(body)); err == nil {
			t.Fatalf("invalid MCP stream message accepted: %s", body)
		}
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe"}]}}`,
		`{"jsonrpc":"2.0","id":"request-1","error":{"code":-32602,"message":"bad input","data":{"detail":"safe"}}}`,
	} {
		if _, err := ParseResponse(domain.ProtocolMCPStreamable, "application/json", []byte(body)); err != nil {
			t.Fatalf("valid MCP response rejected: %s: %v", body, err)
		}
	}
	request := []byte(`{"jsonrpc":"2.0","method":"sampling/createMessage","params":{"messages":[]}}`)
	if _, err := ParseStreamEvent(domain.ProtocolMCPStreamable, request); err != nil {
		t.Fatalf("valid server request stream message rejected: %v", err)
	}
}

func TestMalformedResponseEnvelopesFailClosed(t *testing.T) {
	for _, protocolType := range []domain.Protocol{domain.ProtocolOpenAIChat, domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic, domain.ProtocolGemini, domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable} {
		for _, body := range []string{`{}`, `[]`, `{"unknown":"dev@example.com"}`} {
			if _, err := ParseResponse(protocolType, "application/json", []byte(body)); err == nil {
				t.Fatalf("protocol %s accepted malformed response %s", protocolType, body)
			}
		}
	}
}

func TestNestedJSONStringFieldsRoundTripAtLeafLevel(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"notify","arguments":"{\"contact\":\"dev@example.com\",\"nested\":\"{\\\"phone\\\":\\\"13800138000\\\"}\"}"}}]}]}`)
	document, err := Parse("/v1/chat/completions", "application/json", "", body)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Fields) != 2 {
		t.Fatalf("fields=%+v", document.Fields)
	}
	replacements := map[string]string{}
	for _, field := range document.Fields {
		replacements[field.Path] = "[[VEIL_TEST_0123456789ABCDEF]]"
	}
	rebuilt, err := document.Replace(replacements)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(rebuilt, &outer); err != nil {
		t.Fatal(err)
	}
	arguments := outer.Messages[0].ToolCalls[0].Function.Arguments
	var first map[string]any
	if err := json.Unmarshal([]byte(arguments), &first); err != nil {
		t.Fatalf("arguments stopped being JSON string content: %v", err)
	}
	nested, ok := first["nested"].(string)
	if !ok {
		t.Fatalf("nested type changed: %#v", first)
	}
	var second map[string]any
	if err := json.Unmarshal([]byte(nested), &second); err != nil {
		t.Fatalf("nested content stopped being JSON: %v", err)
	}
	if first["contact"] != "[[VEIL_TEST_0123456789ABCDEF]]" || second["phone"] != "[[VEIL_TEST_0123456789ABCDEF]]" {
		t.Fatalf("leaf replacements missing: %#v %#v", first, second)
	}
}

func TestToolPayloadKeysCannotImpersonateIntegrityFields(t *testing.T) {
	tests := []struct {
		endpoint string
		body     string
	}{
		{"/v1/chat/completions", `{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"x","arguments":"{\"thinking\":\"dev@example.com\",\"signature\":\"ghp_abcdefghijklmnopqrstuvwxyz\"}"}}]}]}`},
		{"/v1/responses", `{"input":[{"type":"function_call","signature":"server-integrity","arguments":{"thinking":"dev@example.com","signature":"ghp_abcdefghijklmnopqrstuvwxyz"}}]}`},
		{"/v1/messages", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","input":{"thinking":"dev@example.com","signature":"ghp_abcdefghijklmnopqrstuvwxyz"}}]}]}`},
		{"/v1beta/models/gemini-2.5-pro:generateContent", `{"contents":[{"parts":[{"functionCall":{"args":{"thinking":"dev@example.com","signature":"ghp_abcdefghijklmnopqrstuvwxyz"}}}]}]}`},
		{"/mcp", `{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"thinking":"dev@example.com","signature":"ghp_abcdefghijklmnopqrstuvwxyz"}}}`},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			document, err := Parse(test.endpoint, "application/json", "", []byte(test.body))
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]bool{}
			for _, field := range document.Fields {
				values[field.Text] = true
			}
			if !values["dev@example.com"] || !values["ghp_abcdefghijklmnopqrstuvwxyz"] || values["server-integrity"] {
				t.Fatalf("unsafe extraction fields=%+v", document.Fields)
			}
		})
	}
}

func TestExcessiveContentNestingFailsClosed(t *testing.T) {
	var input any = "secret"
	for i := 0; i < maxValueDepth+2; i++ {
		input = map[string]any{"child": input}
	}
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse("/v1/responses", "application/json", "", body)
	var veilErr *domain.VeilError
	if !errors.As(err, &veilErr) || veilErr.Code != domain.ErrUnknownProtocol {
		t.Fatalf("expected fail-closed nesting error, got %v", err)
	}
}

func TestStreamEventRejectsTrailingJSON(t *testing.T) {
	if _, err := ParseStreamEvent(domain.ProtocolOpenAIResponses, []byte(`{"delta":"safe"}{"delta":"ignored"}`)); err == nil {
		t.Fatal("stream event accepted trailing JSON")
	}
}

func TestMalformedStreamEnvelopesFailClosed(t *testing.T) {
	for _, test := range []struct {
		protocol domain.Protocol
		body     string
	}{
		{domain.ProtocolOpenAIChat, `{"delta":"safe"}`},
		{domain.ProtocolOpenAIResponses, `{"delta":"safe"}`},
		{domain.ProtocolAnthropic, `{"delta":{"text":"safe"}}`},
		{domain.ProtocolGemini, `{"text":"safe"}`},
		{domain.ProtocolMCPHTTP, `{"jsonrpc":"2.0","value":"safe"}`},
		{domain.ProtocolMCPStreamable, `[]`},
	} {
		if _, err := ParseStreamEvent(test.protocol, []byte(test.body)); err == nil {
			t.Fatalf("protocol %s accepted malformed stream envelope %s", test.protocol, test.body)
		}
	}
}

func TestExpectedRouteProtocolPreventsEndpointConfusion(t *testing.T) {
	if _, err := ParseExpected(domain.ProtocolAnthropic, "/v1/responses", "application/json", "", []byte(`{"input":"safe"}`)); err == nil {
		t.Fatal("route accepted an endpoint from another protocol")
	}
	document, err := ParseExpected(domain.ProtocolMCPStreamable, "/mcp", "application/json", "", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"value":"safe"}}}`))
	if err != nil || document.Protocol != domain.ProtocolMCPStreamable || len(document.Fields) != 1 {
		t.Fatalf("document=%+v err=%v", document, err)
	}
}

func FuzzParseNeverAcceptsMalformedTrailingData(f *testing.F) {
	f.Add([]byte(`{"input":"hello"}`))
	f.Add([]byte(`{"input":"hello"}{"second":true}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		document, err := Parse("/v1/responses", "application/json", "", body)
		if err == nil {
			result, replaceErr := document.Replace(nil)
			if replaceErr != nil || !json.Valid(result) {
				t.Fatalf("accepted document did not round trip: %s %v", result, replaceErr)
			}
		}
	})
}

func FuzzExpectedProtocolEndpointCannotTraverse(f *testing.F) {
	for _, seed := range []string{
		"/v1/responses",
		"/v1/responses/",
		"/v1/../responses",
		"/route/other/v1/responses",
		"//evil.example/v1/responses",
		"/v1/responses/../../chat/completions",
		"/v1/responses%2f..%2fchat/completions",
		"/v1\\responses",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		resolved, err := ResolveEndpoint(domain.ProtocolOpenAIResponses, endpoint)
		if err != nil {
			return
		}
		if resolved != domain.ProtocolOpenAIResponses || endpoint != "/v1/responses" && endpoint != "/v1/responses/" {
			t.Fatal("expected-protocol route accepted a non-canonical or traversal-bearing endpoint")
		}
	})
}

func contains(text, part string) bool {
	for i := 0; i+len(part) <= len(text); i++ {
		if text[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
