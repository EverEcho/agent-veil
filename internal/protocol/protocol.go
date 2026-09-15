package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"sort"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

type Field struct {
	Path      string
	Text      string
	path      []any
	jsonPaths [][]any
}

type Document struct {
	Protocol      domain.Protocol
	root          any
	original      []byte
	Fields        []Field
	extractionErr error
}

const (
	maxValueDepth       = 16
	maxEmbeddedJSONSize = 1 << 20
	MaxEndpointBytes    = 4096
)

// ContentProtectedProtocols returns the protocols whose request, response, and
// streaming envelopes are all implemented by this package. Keep unsupported or
// partially implemented transports out of this list: callers use it as the
// runtime capability boundary for Protected coverage claims.
func ContentProtectedProtocols() []domain.Protocol {
	return []domain.Protocol{
		domain.ProtocolOpenAIChat,
		domain.ProtocolOpenAIResponses,
		domain.ProtocolAnthropic,
		domain.ProtocolGemini,
		domain.ProtocolMCPHTTP,
		domain.ProtocolMCPStreamable,
		domain.ProtocolMCPLegacySSE,
	}
}

func SupportsContentProtection(protocolType domain.Protocol) bool {
	for _, supported := range ContentProtectedProtocols() {
		if protocolType == supported {
			return true
		}
	}
	return false
}

func Parse(endpoint, contentType, contentEncoding string, body []byte) (*Document, error) {
	return ParseExpected("", endpoint, contentType, contentEncoding, body)
}

func ParseExpected(expected domain.Protocol, endpoint, contentType, contentEncoding string, body []byte) (*Document, error) {
	if strings.TrimSpace(contentEncoding) != "" && !strings.EqualFold(contentEncoding, "identity") {
		return nil, domain.NewError(domain.ErrUnsupportedEncoding, "parse request", "only identity content encoding is supported")
	}
	if !MediaTypeIs(contentType, "application/json") {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "protocol endpoint requires application/json")
	}
	protocol, err := ResolveEndpoint(expected, endpoint)
	if err != nil {
		return nil, err
	}
	if err := jsonsafe.Validate(body); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "body is not valid unambiguous JSON")
	}
	var root any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "body is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "body contains trailing data")
	}
	if !validRequestEnvelope(protocol, root) {
		return nil, domain.NewError(domain.ErrUnknownProtocol, "parse request", "body does not match the protected protocol envelope")
	}
	document := &Document{Protocol: protocol, root: root, original: append([]byte(nil), body...)}
	switch protocol {
	case domain.ProtocolOpenAIChat:
		extractChat(document)
	case domain.ProtocolOpenAIResponses:
		extractResponses(document)
	case domain.ProtocolAnthropic:
		extractAnthropic(document)
	case domain.ProtocolGemini:
		extractGemini(document)
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable, domain.ProtocolMCPLegacySSE:
		extractMCP(document)
	}
	if document.extractionErr != nil {
		return nil, document.extractionErr
	}
	return document, nil
}

// MediaTypeIs parses the complete media type so malformed parameters and
// prefix lookalikes cannot be mistaken for a supported representation.
func MediaTypeIs(value, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, expected)
}

// ResolveEndpoint binds a request path to one implemented protocol and rejects
// ambiguous or traversal-bearing paths before they can be joined to an upstream
// base path.
func ResolveEndpoint(expected domain.Protocol, endpoint string) (domain.Protocol, error) {
	if len(endpoint) == 0 || len(endpoint) > MaxEndpointBytes || endpoint[0] != '/' || strings.Contains(endpoint, "//") || strings.ContainsRune(endpoint, '\\') {
		return "", domain.NewError(domain.ErrUnknownProtocol, "parse request", "endpoint is malformed")
	}
	for _, segment := range strings.Split(endpoint, "/") {
		if segment == "." || segment == ".." {
			return "", domain.NewError(domain.ErrUnknownProtocol, "parse request", "endpoint contains traversal")
		}
	}
	var protocol domain.Protocol
	cleanEndpoint := strings.TrimSuffix(endpoint, "/")
	switch cleanEndpoint {
	case "/v1/chat/completions":
		protocol = domain.ProtocolOpenAIChat
	case "/responses", "/v1/responses":
		protocol = domain.ProtocolOpenAIResponses
	case "/v1/messages":
		protocol = domain.ProtocolAnthropic
	case "/mcp", "/v1/mcp":
		if expected == domain.ProtocolMCPStreamable {
			protocol = domain.ProtocolMCPStreamable
		} else if expected == domain.ProtocolMCPLegacySSE {
			protocol = domain.ProtocolMCPLegacySSE
		} else {
			protocol = domain.ProtocolMCPHTTP
		}
	default:
		if strings.Contains(cleanEndpoint, "/models/") && (strings.HasSuffix(cleanEndpoint, ":generateContent") || strings.HasSuffix(cleanEndpoint, ":streamGenerateContent")) {
			protocol = domain.ProtocolGemini
		} else {
			return "", domain.NewError(domain.ErrUnknownProtocol, "parse request", "endpoint is not supported")
		}
	}
	if expected != "" && protocol != expected {
		return "", domain.NewError(domain.ErrUnknownProtocol, "parse request", "endpoint does not match the protected route protocol")
	}
	return protocol, nil
}

func validRequestEnvelope(protocolType domain.Protocol, root any) bool {
	object, ok := root.(map[string]any)
	if !ok {
		return false
	}
	switch protocolType {
	case domain.ProtocolOpenAIChat:
		_, ok = object["messages"].([]any)
		return ok
	case domain.ProtocolOpenAIResponses:
		_, hasInput := object["input"]
		_, hasInstructions := object["instructions"]
		return hasInput || hasInstructions
	case domain.ProtocolAnthropic:
		_, ok = object["messages"].([]any)
		return ok
	case domain.ProtocolGemini:
		_, ok = object["contents"].([]any)
		return ok
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable, domain.ProtocolMCPLegacySSE:
		return validMCPRequestEnvelope(object)
	default:
		return false
	}
}

func validMCPRequestEnvelope(object map[string]any) bool {
	version, versionOK := object["jsonrpc"].(string)
	method, methodOK := object["method"].(string)
	if !versionOK || version != "2.0" || !methodOK || strings.TrimSpace(method) == "" {
		return false
	}
	if _, hasResult := object["result"]; hasResult {
		return false
	}
	if _, hasError := object["error"]; hasError {
		return false
	}
	if params, exists := object["params"]; exists {
		if _, ok := params.(map[string]any); !ok {
			return false
		}
	}
	if id, exists := object["id"]; exists && !validMCPID(id) {
		return false
	}
	return true
}

func validMCPID(value any) bool {
	switch value.(type) {
	case string, json.Number:
		return true
	default:
		return false
	}
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
	if len(replacements) == 0 && d.original != nil {
		return append([]byte(nil), d.original...), nil
	}
	for _, field := range d.Fields {
		value, ok := replacements[field.Path]
		if !ok {
			continue
		}
		if len(field.jsonPaths) > 0 {
			outer, err := getString(d.root, field.path)
			if err != nil {
				return nil, err
			}
			value, err = replaceEmbeddedJSON(outer, field.jsonPaths, value)
			if err != nil {
				return nil, err
			}
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
	if depth > maxValueDepth {
		d.failDepth()
		return
	}
	switch typed := value.(type) {
	case string:
		addText(d, typed, path, nil, depth)
	case []any:
		for i, child := range typed {
			extractResponseInput(d, child, appendPath(path, i), depth+1)
		}
	case map[string]any:
		typeName, _ := typed["type"].(string)
		for _, key := range sortedKeys(typed) {
			child := typed[key]
			switch key {
			case "type", "role", "name", "id", "call_id", "status":
				continue
			case "signature", "thinking", "redacted_thinking":
				if responseIntegrityContainer(typeName) {
					continue
				}
			case "encrypted_content":
				if encryptedContentContainer(typeName) {
					continue
				}
			case "arguments", "input", "output":
				extractValue(d, child, appendPath(path, key), depth+1)
				continue
			default:
			}
			extractResponseInput(d, child, appendPath(path, key), depth+1)
		}
	}
}

func responseIntegrityContainer(typeName string) bool {
	switch typeName {
	case "function_call", "custom_tool_call", "reasoning", "thinking", "redacted_thinking":
		return true
	default:
		return false
	}
}

func encryptedContentContainer(typeName string) bool {
	switch typeName {
	case "reasoning", "compaction":
		return true
	default:
		return false
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
		addText(d, typed, path, nil, 0)
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
	if depth > maxValueDepth {
		d.failDepth()
		return
	}
	switch typed := value.(type) {
	case string:
		addText(d, typed, path, nil, depth)
	case []any:
		for i, child := range typed {
			extractValue(d, child, appendPath(path, i), depth+1)
		}
	case map[string]any:
		for _, key := range sortedKeys(typed) {
			child := typed[key]
			extractValue(d, child, appendPath(path, key), depth+1)
		}
	}
}

func addString(d *Document, object map[string]any, key string, base []any) {
	if value, ok := object[key].(string); ok {
		path := appendPath(base, key)
		addText(d, value, path, nil, 0)
	}
}

func addText(d *Document, value string, path []any, jsonPaths [][]any, depth int) {
	if depth < maxValueDepth && len(value) <= maxEmbeddedJSONSize {
		if embedded, ok := decodeEmbeddedJSON(value); ok {
			extractEmbedded(d, embedded, path, jsonPaths, nil, depth+1)
			return
		}
	}
	fieldPath := pathString(path)
	for _, nested := range jsonPaths {
		fieldPath += "/$json" + pathString(nested)
	}
	d.Fields = append(d.Fields, Field{Path: fieldPath, Text: value, path: path, jsonPaths: clonePaths(jsonPaths)})
}

func extractEmbedded(d *Document, value any, outerPath []any, parents [][]any, path []any, depth int) {
	if depth > maxValueDepth {
		d.failDepth()
		return
	}
	switch typed := value.(type) {
	case string:
		chain := append(clonePaths(parents), appendPath(nil, path...))
		addText(d, typed, outerPath, chain, depth)
	case []any:
		for i, child := range typed {
			extractEmbedded(d, child, outerPath, parents, appendPath(path, i), depth+1)
		}
	case map[string]any:
		for _, key := range sortedKeys(typed) {
			child := typed[key]
			extractEmbedded(d, child, outerPath, parents, appendPath(path, key), depth+1)
		}
	}
}

func decodeEmbeddedJSON(value string) (any, bool) {
	if err := jsonsafe.Validate([]byte(value)); err != nil {
		return nil, false
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	switch decoded.(type) {
	case map[string]any, []any:
		return decoded, true
	default:
		return nil, false
	}
}

func replaceEmbeddedJSON(encoded string, paths [][]any, replacement string) (string, error) {
	decoded, ok := decodeEmbeddedJSON(encoded)
	if !ok {
		return "", domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "embedded JSON field is no longer valid")
	}
	currentPath := paths[0]
	if len(paths) == 1 {
		if err := set(decoded, currentPath, replacement); err != nil {
			return "", err
		}
	} else {
		child, err := getString(decoded, currentPath)
		if err != nil {
			return "", err
		}
		child, err = replaceEmbeddedJSON(child, paths[1:], replacement)
		if err != nil {
			return "", err
		}
		if err := set(decoded, currentPath, child); err != nil {
			return "", err
		}
	}
	result, err := json.Marshal(decoded)
	if err != nil {
		return "", domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "embedded JSON cannot be encoded")
	}
	return string(result), nil
}

func clonePaths(paths [][]any) [][]any {
	result := make([][]any, len(paths))
	for i, path := range paths {
		result[i] = appendPath(nil, path...)
	}
	return result
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (d *Document) failDepth() {
	if d.extractionErr == nil {
		d.extractionErr = domain.NewError(domain.ErrUnknownProtocol, "parse content", "content nesting exceeds safety limit")
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
			escaped := strings.ReplaceAll(v, "~", "~0")
			b.WriteString(strings.ReplaceAll(escaped, "/", "~1"))
		case int:
			fmt.Fprintf(&b, "/%d", v)
		}
	}
	return b.String()
}

func getString(root any, path []any) (string, error) {
	current := root
	for _, part := range path {
		switch key := part.(type) {
		case string:
			object, ok := current.(map[string]any)
			if !ok {
				return "", domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "field path changed type")
			}
			current = object[key]
		case int:
			array, ok := current.([]any)
			if !ok || key < 0 || key >= len(array) {
				return "", domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "field path is invalid")
			}
			current = array[key]
		}
	}
	value, ok := current.(string)
	if !ok {
		return "", domain.NewError(domain.ErrInvalidContract, "rebuild protocol", "field is no longer a string")
	}
	return value, nil
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
