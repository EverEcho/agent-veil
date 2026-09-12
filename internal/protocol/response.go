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
	if !validResponseEnvelope(protocol, root) {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "body does not match the protected protocol envelope")
	}
	document := &Document{Protocol: protocol, root: root}
	extractProtocolError(document, root)
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
	if document.extractionErr != nil {
		return nil, document.extractionErr
	}
	return document, nil
}

func validResponseEnvelope(protocolType domain.Protocol, root any) bool {
	object, ok := root.(map[string]any)
	if !ok {
		return false
	}
	if _, hasError := object["error"]; hasError {
		return true
	}
	switch protocolType {
	case domain.ProtocolOpenAIChat:
		_, ok = object["choices"].([]any)
		return ok
	case domain.ProtocolOpenAIResponses:
		_, hasOutput := object["output"]
		_, hasOutputText := object["output_text"].(string)
		return hasOutput || hasOutputText
	case domain.ProtocolAnthropic:
		_, ok = object["content"].([]any)
		return ok
	case domain.ProtocolGemini:
		_, ok = object["candidates"].([]any)
		return ok
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable:
		version, versionOK := object["jsonrpc"].(string)
		_, hasResult := object["result"]
		method, hasMethod := object["method"].(string)
		return versionOK && version == "2.0" && (hasResult || hasMethod && strings.TrimSpace(method) != "")
	default:
		return false
	}
}

func ParseStreamEvent(protocol domain.Protocol, data []byte) (*Document, error) {
	var root any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "event data is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "event data contains trailing JSON")
	}
	if !validStreamEnvelope(protocol, root) {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "event data does not match the protected protocol envelope")
	}
	document := &Document{Protocol: protocol, root: root}
	extractProtocolError(document, root)
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
	if document.extractionErr != nil {
		return nil, document.extractionErr
	}
	return document, nil
}

func validStreamEnvelope(protocolType domain.Protocol, root any) bool {
	object, ok := root.(map[string]any)
	if !ok {
		return false
	}
	if _, hasError := object["error"]; hasError {
		return true
	}
	switch protocolType {
	case domain.ProtocolOpenAIChat:
		_, ok = object["choices"].([]any)
		return ok
	case domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic:
		typeName, ok := object["type"].(string)
		return ok && strings.TrimSpace(typeName) != ""
	case domain.ProtocolGemini:
		_, ok = object["candidates"].([]any)
		return ok
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable:
		version, versionOK := object["jsonrpc"].(string)
		_, hasResult := object["result"]
		method, hasMethod := object["method"].(string)
		return versionOK && version == "2.0" && (hasResult || hasMethod && strings.TrimSpace(method) != "")
	default:
		return false
	}
}

func extractProtocolError(document *Document, root any) {
	object, ok := root.(map[string]any)
	if !ok {
		return
	}
	if value, exists := object["error"]; exists {
		extractValue(document, value, []any{"error"}, 0)
	}
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
