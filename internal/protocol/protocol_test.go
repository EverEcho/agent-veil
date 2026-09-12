package protocol

import (
	"encoding/json"
	"errors"
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

func TestUnknownProtocolAndCompressionFailClosed(t *testing.T) {
	for _, item := range []struct{ endpoint, contentType, encoding string }{{"/unknown", "application/json", ""}, {"/v1/responses", "text/plain", ""}, {"/v1/responses", "application/json", "gzip"}} {
		_, err := Parse(item.endpoint, item.contentType, item.encoding, []byte(`{}`))
		var veilErr *domain.VeilError
		if !errors.As(err, &veilErr) {
			t.Fatalf("expected fail-closed error for %+v", item)
		}
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
	} {
		if _, err := Parse(test.endpoint, "application/json", "", []byte(test.body)); err == nil {
			t.Fatalf("%s accepted malformed envelope %s", test.endpoint, test.body)
		}
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
		document, err := Parse("/v1/responses", "application/json", "", body)
		if err == nil {
			result, replaceErr := document.Replace(nil)
			if replaceErr != nil || !json.Valid(result) {
				t.Fatalf("accepted document did not round trip: %s %v", result, replaceErr)
			}
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
