package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

func ParseResponse(protocol domain.Protocol, contentType string, body []byte) (*Document, error) {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0])); mediaType != "application/json" {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "protocol response requires application/json")
	}
	var root any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "body is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "body contains trailing data")
	}
	document := &Document{Protocol: protocol, root: root}
	switch protocol {
	case domain.ProtocolOpenAIChat:
		extractChatResponse(document)
	case domain.ProtocolOpenAIResponses:
		extractResponses(document)
		if object, ok := root.(map[string]any); ok {
			extractResponseInput(document, object["output"], []any{"output"}, 0)
			addString(document, object, "output_text", nil)
		}
	case domain.ProtocolAnthropic:
		if object, ok := root.(map[string]any); ok {
			extractContent(document, object["content"], []any{"content"})
		}
	case domain.ProtocolGemini:
		extractGeminiResponse(document)
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable:
		extractMCP(document)
	default:
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "protocol is unsupported")
	}
	return document, nil
}

func ParseStreamEvent(protocol domain.Protocol, data []byte) (*Document, error) {
	var root any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "event data is not valid JSON")
	}
	document := &Document{Protocol: protocol, root: root}
	switch protocol {
	case domain.ProtocolOpenAIChat:
		extractChatResponse(document)
	case domain.ProtocolOpenAIResponses:
		if object, ok := root.(map[string]any); ok {
			if value, ok := object["delta"].(string); ok {
				document.Fields = append(document.Fields, Field{Path: "/delta", Text: value, path: []any{"delta"}})
			} else {
				extractResponseInput(document, object["delta"], []any{"delta"}, 0)
			}
		}
	case domain.ProtocolAnthropic:
		if object, ok := root.(map[string]any); ok {
			if delta, ok := object["delta"].(map[string]any); ok {
				addString(document, delta, "text", []any{"delta"})
				addString(document, delta, "partial_json", []any{"delta"})
			}
		}
	case domain.ProtocolGemini:
		extractGeminiResponse(document)
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable:
		extractMCP(document)
	default:
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "protocol is unsupported")
	}
	return document, nil
}

func extractChatResponse(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	choices, _ := root["choices"].([]any)
	for i, raw := range choices {
		choice, _ := raw.(map[string]any)
		for _, key := range []string{"message", "delta"} {
			if message, ok := choice[key].(map[string]any); ok {
				base := []any{"choices", i, key}
				extractContent(d, message["content"], appendPath(base, "content"))
				if calls, ok := message["tool_calls"].([]any); ok {
					for j, rawCall := range calls {
						if call, ok := rawCall.(map[string]any); ok {
							if function, ok := call["function"].(map[string]any); ok {
								addString(d, function, "arguments", appendPath(base, "tool_calls", j, "function"))
							}
						}
					}
				}
			}
		}
	}
}
func extractGeminiResponse(d *Document) {
	root, ok := d.root.(map[string]any)
	if !ok {
		return
	}
	candidates, _ := root["candidates"].([]any)
	for i, raw := range candidates {
		candidate, _ := raw.(map[string]any)
		if content, ok := candidate["content"].(map[string]any); ok {
			extractGeminiParts(d, content["parts"], []any{"candidates", i, "content", "parts"})
		}
	}
}
