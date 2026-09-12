package protocol

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type Field struct {
	Path string
	Text string
	path []any
}

type Document struct {
	Protocol domain.Protocol
	root     any
	Fields   []Field
}

func Parse(endpoint, contentType, contentEncoding string, body []byte) (*Document, error) {
	if strings.TrimSpace(contentEncoding) != "" && !strings.EqualFold(contentEncoding, "identity") {
		return nil, domain.NewError(domain.ErrUnsupportedEncoding, "parse request", "only identity content encoding is supported")
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0])); mediaType != "application/json" {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "protocol endpoint requires application/json")
	}
	var protocol domain.Protocol
	cleanEndpoint := strings.TrimSuffix(endpoint, "/")
	switch cleanEndpoint {
	case "/v1/chat/completions":
		protocol = domain.ProtocolOpenAIChat
	case "/v1/responses":
		protocol = domain.ProtocolOpenAIResponses
	case "/v1/messages":
		protocol = domain.ProtocolAnthropic
	case "/mcp", "/v1/mcp":
		protocol = domain.ProtocolMCPHTTP
	default:
		if strings.Contains(cleanEndpoint, "/models/") && (strings.HasSuffix(cleanEndpoint, ":generateContent") || strings.HasSuffix(cleanEndpoint, ":streamGenerateContent")) {
			protocol = domain.ProtocolGemini
		} else {
			return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "endpoint is not supported")
		}
	}
	var root any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "body is not valid JSON")
	}
	document := &Document{Protocol: protocol, root: root}
	switch protocol {
	case domain.ProtocolOpenAIChat:
		extractChat(document)
	case domain.ProtocolOpenAIResponses:
		extractResponses(document)
	case domain.ProtocolAnthropic:
		extractAnthropic(document)
	case domain.ProtocolGemini:
		extractGemini(document)
	case domain.ProtocolMCPHTTP:
		extractMCP(document)
	}
	return document, nil
}

func extractGemini(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	if system, ok := root["systemInstruction"].(map[string]any); ok {
		extractGeminiParts(d, system["parts"], []any{"systemInstruction", "parts"})
	}
	if contents, ok := root["contents"].([]any); ok {
		for i, raw := range contents {
			if content, ok := raw.(map[string]any); ok {
				extractGeminiParts(d, content["parts"], []any{"contents", i, "parts"})
			}
		}
	}
}

func extractGeminiParts(d *Document, value any, path []any) {
	parts, _ := value.([]any)
	for i, raw := range parts {
		part, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		base := appendPath(path, i)
		addString(d, part, "text", base)
		if call, ok := part["functionCall"].(map[string]any); ok {
			extractValue(d, call["args"], appendPath(base, "functionCall", "args"), 0)
		}
		if response, ok := part["functionResponse"].(map[string]any); ok {
			extractValue(d, response["response"], appendPath(base, "functionResponse", "response"), 0)
		}
	}
}

func extractMCP(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"params", "result"} {
		extractValue(d, root[key], []any{key}, 0)
	}
}

func (d *Document) Replace(replacements map[string]string) ([]byte, error) {
	for _, field := range d.Fields {
		value, ok := replacements[field.Path]
		if !ok {
			continue
		}
		if err := set(d.root, field.path, value); err != nil {
			return nil, err
		}
	}
	return json.Marshal(d.root)
}

func extractChat(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	messages, _ := root["messages"].([]any)
	for i, raw := range messages {
		message, _ := raw.(map[string]any)
		base := []any{"messages", i}
		extractContent(d, message["content"], appendPath(base, "content"))
		if call, ok := message["function_call"].(map[string]any); ok {
			addString(d, call, "arguments", appendPath(base, "function_call"))
		}
		if calls, ok := message["tool_calls"].([]any); ok {
			for j, rawCall := range calls {
				if call, ok := rawCall.(map[string]any); ok {
					if fn, ok := call["function"].(map[string]any); ok {
						addString(d, fn, "arguments", appendPath(base, "tool_calls", j, "function"))
					}
				}
			}
		}
	}
}

func extractResponses(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	extractValue(d, root["instructions"], []any{"instructions"}, 0)
	extractResponseInput(d, root["input"], []any{"input"}, 0)
}

func extractResponseInput(d *Document, value any, path []any, depth int) {
	if depth > 16 {
		return
	}
	switch typed := value.(type) {
	case string:
		d.Fields = append(d.Fields, Field{Path: pathString(path), Text: typed, path: path})
	case []any:
		for i, child := range typed {
			extractResponseInput(d, child, appendPath(path, i), depth+1)
		}
	case map[string]any:
		for key, child := range typed {
			switch key {
			case "type", "role", "name", "id", "call_id", "status", "signature", "thinking", "redacted_thinking":
				continue
			default:
				extractResponseInput(d, child, appendPath(path, key), depth+1)
			}
		}
	}
}

func extractAnthropic(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	extractContent(d, root["system"], []any{"system"})
	if messages, ok := root["messages"].([]any); ok {
		for i, raw := range messages {
			if message, ok := raw.(map[string]any); ok {
				extractContent(d, message["content"], []any{"messages", i, "content"})
			}
		}
	}
}

func extractContent(d *Document, value any, path []any) {
	switch typed := value.(type) {
	case string:
		d.Fields = append(d.Fields, Field{Path: pathString(path), Text: typed, path: path})
	case []any:
		for i, raw := range typed {
			block, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			typeName, _ := block["type"].(string)
			base := appendPath(path, i)
			switch typeName {
			case "text", "input_text", "output_text":
				addString(d, block, "text", base)
			case "tool_use":
				extractValue(d, block["input"], appendPath(base, "input"), 0)
			case "tool_result":
				extractContent(d, block["content"], appendPath(base, "content"))
			case "function_call", "custom_tool_call":
				extractValue(d, block["arguments"], appendPath(base, "arguments"), 0)
			}
		}
	}
}

func extractValue(d *Document, value any, path []any, depth int) {
	if depth > 16 {
		return
	}
	switch typed := value.(type) {
	case string:
		d.Fields = append(d.Fields, Field{Path: pathString(path), Text: typed, path: path})
	case []any:
		for i, child := range typed {
			extractValue(d, child, appendPath(path, i), depth+1)
		}
	case map[string]any:
		for key, child := range typed {
			if key == "thinking" || key == "redacted_thinking" || key == "signature" {
				continue
			}
			extractValue(d, child, appendPath(path, key), depth+1)
		}
	}
}

func addString(d *Document, object map[string]any, key string, base []any) {
	if value, ok := object[key].(string); ok {
		path := appendPath(base, key)
		d.Fields = append(d.Fields, Field{Path: pathString(path), Text: value, path: path})
	}
}

func appendPath(base []any, values ...any) []any {
	result := append([]any(nil), base...)
	return append(result, values...)
}
func pathString(path []any) string {
	var b strings.Builder
	for _, part := range path {
		switch v := part.(type) {
		case string:
			b.WriteByte('/')
			b.WriteString(strings.ReplaceAll(v, "~", "~0"))
		case int:
			fmt.Fprintf(&b, "/%d", v)
		}
	}
	return b.String()
}

func set(root any, path []any, value string) error {
	current := root
	for i, part := range path {
		last := i == len(path)-1
		switch key := part.(type) {
		case string:
			object, ok := current.(map[string]any)
			if !ok {
				return domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "field path changed type")
			}
			if last {
				object[key] = value
				return nil
			}
			current = object[key]
		case int:
			array, ok := current.([]any)
			if !ok || key < 0 || key >= len(array) {
				return domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "field path is invalid")
			}
			if last {
				array[key] = value
				return nil
			}
			current = array[key]
		}
	}
	return domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "empty field path")
}
