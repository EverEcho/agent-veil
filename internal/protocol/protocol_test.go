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
