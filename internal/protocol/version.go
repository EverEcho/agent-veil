package protocol

import "github.com/agentveil/agentveil/internal/domain"

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

func unsupportedMCPVersion() error {
	return domain.NewError(domain.ErrUnknownProtocol, "validate MCP protocol version", "protocol revision is invalid, ambiguous, or unsupported")
}
