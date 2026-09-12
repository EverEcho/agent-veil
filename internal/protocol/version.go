package protocol

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const (
	HeaderMCPProtocolVersion = "MCP-Protocol-Version"

	MCPVersion20250326 = "2025-03-26"
	MCPVersion20250618 = "2025-06-18"
	MCPVersion20251125 = "2025-11-25"
)

// ResolveMCPStreamableVersion fails closed for revisions whose wire contract has
// not been implemented. A missing header retains the compatibility behavior
// specified by the stateful Streamable HTTP revisions.
func ResolveMCPStreamableVersion(values []string) (string, error) {
	if len(values) == 0 {
		return MCPVersion20250326, nil
	}
	if len(values) != 1 {
		return "", unsupportedMCPVersion()
	}
	switch values[0] {
	case MCPVersion20250326, MCPVersion20250618, MCPVersion20251125:
		return values[0], nil
	default:
		return "", unsupportedMCPVersion()
	}
}

// ValidateMCPStreamableAccept enforces the response media ranges required by
// the stateful Streamable HTTP revisions supported by this adapter.
func ValidateMCPStreamableAccept(method string, values []string) error {
	if method == http.MethodDelete {
		return nil
	}
	if method != http.MethodPost && method != http.MethodGet || len(values) == 0 {
		return unsupportedMCPTransportHeader()
	}
	wantsJSON, wantsSSE := false, false
	for _, line := range values {
		for _, item := range strings.Split(line, ",") {
			mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(item))
			if err != nil || !acceptableQuality(parameters["q"]) {
				continue
			}
			switch strings.ToLower(mediaType) {
			case "application/json":
				wantsJSON = true
			case "text/event-stream":
				wantsSSE = true
			}
		}
	}
	if !wantsSSE || method == http.MethodPost && !wantsJSON {
		return unsupportedMCPTransportHeader()
	}
	return nil
}

func acceptableQuality(value string) bool {
	if value == "" {
		return true
	}
	quality, err := strconv.ParseFloat(value, 64)
	return err == nil && quality > 0 && quality <= 1
}

// ValidateMCPStreamableBodyVersion rejects modern per-request version metadata
// that disagrees with the HTTP envelope. Callers pass a body that has already
// passed the strict MCP JSON envelope parser.
func ValidateMCPStreamableBodyVersion(version string, body []byte) error {
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		return unsupportedMCPVersion()
	}
	params, _ := request["params"].(map[string]any)
	metadata, _ := params["_meta"].(map[string]any)
	bodyVersion, exists := metadata["io.modelcontextprotocol/protocolVersion"]
	if !exists {
		return nil
	}
	value, ok := bodyVersion.(string)
	if !ok || value != version {
		return unsupportedMCPVersion()
	}
	return nil
}

func unsupportedMCPVersion() error {
	return domain.NewError(domain.ErrUnknownProtocol, "validate MCP protocol version", "protocol revision is invalid, ambiguous, or unsupported")
}

func unsupportedMCPTransportHeader() error {
	return domain.NewError(domain.ErrUnknownProtocol, "validate MCP transport headers", "Accept does not permit every required response media type")
}
