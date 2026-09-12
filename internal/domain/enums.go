package domain

type SurfaceType string

const (
	SurfaceModelPrimary   SurfaceType = "model_primary"
	SurfaceModelAuxiliary SurfaceType = "model_auxiliary"
	SurfaceModelFallback  SurfaceType = "model_fallback"
	SurfaceVision         SurfaceType = "vision"
	SurfaceEmbedding      SurfaceType = "embedding"
	SurfaceImage          SurfaceType = "image_generation"
	SurfaceAudio          SurfaceType = "audio"
	SurfaceMCPHTTP        SurfaceType = "mcp_http"
	SurfaceMCPStdio       SurfaceType = "mcp_stdio"
	SurfaceToolHTTP       SurfaceType = "tool_http"
	SurfaceBrowser        SurfaceType = "browser"
	SurfaceSubAgent       SurfaceType = "sub_agent"
	SurfaceACP            SurfaceType = "acp"
	SurfaceUnknown        SurfaceType = "unknown"
)

func (v SurfaceType) Valid() bool {
	switch v {
	case SurfaceModelPrimary, SurfaceModelAuxiliary, SurfaceModelFallback,
		SurfaceVision, SurfaceEmbedding, SurfaceImage, SurfaceAudio,
		SurfaceMCPHTTP, SurfaceMCPStdio, SurfaceToolHTTP, SurfaceBrowser,
		SurfaceSubAgent, SurfaceACP, SurfaceUnknown:
		return true
	default:
		return false
	}
}

type Protocol string

const (
	ProtocolOpenAIChat      Protocol = "openai_chat"
	ProtocolOpenAIResponses Protocol = "openai_responses"
	ProtocolAnthropic       Protocol = "anthropic_messages"
	ProtocolGemini          Protocol = "gemini"
	ProtocolMCPHTTP         Protocol = "mcp_http"
	ProtocolMCPStreamable   Protocol = "mcp_streamable_http"
	ProtocolLocalStdio      Protocol = "local_stdio"
	ProtocolUnknown         Protocol = "unknown"
)

func (v Protocol) Valid() bool {
	switch v {
	case ProtocolOpenAIChat, ProtocolOpenAIResponses, ProtocolAnthropic,
		ProtocolGemini, ProtocolMCPHTTP, ProtocolMCPStreamable,
		ProtocolLocalStdio, ProtocolUnknown:
		return true
	default:
		return false
	}
}

type CoverageStatus string

const (
	CoverageProtected   CoverageStatus = "protected"
	CoverageLocal       CoverageStatus = "local"
	CoveragePartial     CoverageStatus = "partial"
	CoverageObserved    CoverageStatus = "observed"
	CoverageUnprotected CoverageStatus = "unprotected"
)

func (v CoverageStatus) Valid() bool {
	switch v {
	case CoverageProtected, CoverageLocal, CoveragePartial, CoverageObserved, CoverageUnprotected:
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionAllow  Action = "allow"
	ActionRedact Action = "redact"
	ActionBlock  Action = "block"
	ActionAsk    Action = "ask"
)

func (v Action) Valid() bool {
	switch v {
	case ActionAllow, ActionRedact, ActionBlock, ActionAsk:
		return true
	default:
		return false
	}
}

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (v Severity) Valid() bool {
	switch v {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

type AuthType string

const (
	AuthPassthrough  AuthType = "passthrough"
	AuthBearer       AuthType = "bearer"
	AuthAnthropicKey AuthType = "anthropic_key"
	AuthGoogleKey    AuthType = "google_key"
	AuthAWSSigV4     AuthType = "aws_sigv4"
	AuthVertexOAuth  AuthType = "vertex_oauth"
	AuthCustom       AuthType = "custom"
)

func (v AuthType) Valid() bool {
	switch v {
	case AuthPassthrough, AuthBearer, AuthAnthropicKey, AuthGoogleKey, AuthAWSSigV4, AuthVertexOAuth, AuthCustom:
		return true
	default:
		return false
	}
}

type NetworkType string

const (
	NetworkDirect      NetworkType = "direct"
	NetworkHTTPProxy   NetworkType = "http_proxy"
	NetworkSOCKS5      NetworkType = "socks5"
	NetworkSystemProxy NetworkType = "system_proxy"
)

func (v NetworkType) Valid() bool {
	switch v {
	case NetworkDirect, NetworkHTTPProxy, NetworkSOCKS5, NetworkSystemProxy:
		return true
	default:
		return false
	}
}

type IntegrationMode string

const (
	ModeLaunch      IntegrationMode = "launch"
	ModeAttach      IntegrationMode = "attach"
	ModeManaged     IntegrationMode = "managed"
	ModeNative      IntegrationMode = "native"
	ModeTransparent IntegrationMode = "transparent"
)

func (v IntegrationMode) Valid() bool {
	switch v {
	case ModeLaunch, ModeAttach, ModeManaged, ModeNative, ModeTransparent:
		return true
	default:
		return false
	}
}
