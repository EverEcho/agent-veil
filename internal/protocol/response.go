package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

func ParseResponse(protocol domain.Protocol, contentType string, body []byte) (*Document, error) {
	if !MediaTypeIs(contentType, "application/json") {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "protocol response requires application/json")
	}
	if err := jsonsafe.Validate(body); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse response", "body is not valid unambiguous JSON")
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
	document := &Document{Protocol: protocol, root: root, original: append([]byte(nil), body...)}
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
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable, domain.ProtocolMCPLegacySSE:
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
	if protocolType == domain.ProtocolMCPHTTP || protocolType == domain.ProtocolMCPStreamable || protocolType == domain.ProtocolMCPLegacySSE {
		return validMCPResponseEnvelope(object)
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
	default:
		return false
	}
}

func ParseStreamEvent(protocol domain.Protocol, data []byte) (*Document, error) {
	if err := jsonsafe.Validate(data); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "event data is not valid unambiguous JSON")
	}
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
			extractResponsesStream(document, object)
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
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable, domain.ProtocolMCPLegacySSE:
		extractMCP(document)
	default:
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse stream event", "protocol is unsupported")
	}
	if document.extractionErr != nil {
		return nil, document.extractionErr
	}
	return document, nil
}

func extractResponsesStream(document *Document, object map[string]any) {
	typeName, _ := object["type"].(string)
	if value, ok := object["delta"].(string); ok {
		document.Fields = append(document.Fields, Field{Path: "/delta", Text: value, path: []any{"delta"}})
	} else {
		extractResponseInput(document, object["delta"], []any{"delta"}, 0)
	}
	switch typeName {
	case "response.output_text.done":
		addString(document, object, "text", nil)
	case "response.content_part.added", "response.content_part.done":
		if part, ok := object["part"].(map[string]any); ok {
			if partType, _ := part["type"].(string); partType == "output_text" {
				addString(document, part, "text", []any{"part"})
			}
		}
	case "response.output_item.added", "response.output_item.done":
		extractResponseInput(document, object["item"], []any{"item"}, 0)
	case "response.completed", "response.failed", "response.incomplete":
		if response, ok := object["response"].(map[string]any); ok {
			extractResponseInput(document, response["output"], []any{"response", "output"}, 0)
		}
	}
}

func validStreamEnvelope(protocolType domain.Protocol, root any) bool {
	object, ok := root.(map[string]any)
	if !ok {
		return false
	}
	if protocolType == domain.ProtocolMCPHTTP || protocolType == domain.ProtocolMCPStreamable || protocolType == domain.ProtocolMCPLegacySSE {
		return validMCPResponseEnvelope(object) || validMCPRequestEnvelope(object)
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
	default:
		return false
	}
}

func validMCPResponseEnvelope(object map[string]any) bool {
	version, versionOK := object["jsonrpc"].(string)
	id, hasID := object["id"]
	if !versionOK || version != "2.0" || !hasID || !validMCPID(id) {
		return false
	}
	result, hasResult := object["result"]
	errorValue, hasError := object["error"]
	if hasResult == hasError {
		return false
	}
	if hasResult {
		_, ok := result.(map[string]any)
		return ok
	}
	errorObject, ok := errorValue.(map[string]any)
	if !ok {
		return false
	}
	code, codeOK := errorObject["code"].(json.Number)
	_, messageOK := errorObject["message"].(string)
	if !codeOK || !messageOK {
		return false
	}
	_, err := strconv.ParseInt(code.String(), 10, 64)
	return err == nil
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
