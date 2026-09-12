package integration

import "testing"

func TestValidateJSONCAcceptsCommentsAndTrailingCommas(t *testing.T) {
	content := []byte(`{
  // line comment
  "object": { "value": "comma,} and // text", },
  "array": [1, 2,],
  /* block comment */
}`)
	if _, err := validateJSONC(content); err != nil {
		t.Fatal(err)
	}
}

func TestValidateJSONCRejectsYAMLJSON5DuplicatesAndDeepNesting(t *testing.T) {
	deep := ""
	for range maxJSONNestingDepth + 2 {
		deep += "["
	}
	for range maxJSONNestingDepth + 2 {
		deep += "]"
	}
	for _, content := range []string{
		"model: corp/main",
		`{'model':'corp/main'}`,
		`{model:"corp/main"}`,
		`{"model":"one","model":"two"}`,
		`{"value": NaN}`,
		deep,
	} {
		if _, err := validateJSONC([]byte(content)); err == nil {
			t.Fatalf("accepted invalid JSONC: %q", content)
		}
	}
	if _, err := validateJSONC([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestAgentJSONCParsersRejectDuplicateSecurityFields(t *testing.T) {
	if _, _, err := ParseOpenCodeConfig([]byte(`{"model":"anthropic/one","model":"corp/two"}`)); err == nil {
		t.Fatal("OpenCode duplicate model field was accepted")
	}
	if _, _, err := ParseZedConfig([]byte(`{"context_servers":{},"context_servers":{"hidden":{"url":"https://mcp.example"}}}`)); err == nil {
		t.Fatal("Zed duplicate context_servers field was accepted")
	}
	if _, err := ParseClineProviders([]byte(`{"providers":{},"providers":{"hidden":{"settings":{}}}}`)); err == nil {
		t.Fatal("Cline duplicate providers field was accepted")
	}
	if _, _, err := ParseCursorMCP([]byte(`{"mcpServers":{},"mcpServers":{"hidden":{"command":"server"}}}`)); err == nil {
		t.Fatal("Cursor duplicate mcpServers field was accepted")
	}
}
