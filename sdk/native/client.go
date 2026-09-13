// Package native provides the trusted-host control-plane client used by Native
// and Managed Agent integrations. Integrations report manifests and maintain
// leases; request inspection and policy enforcement remain exclusively in Core.
package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const (
	apiVersion       = "v1"
	apiVersionHeader = "X-AgentVeil-API-Version"
	maxResponseBytes = 2 << 20
	maxLeaseTTL      = time.Hour
	minTokenBytes    = 32
	maxTokenBytes    = 512
)

type AgentManifest = domain.AgentManifest
type AgentInstance = domain.AgentInstance
type EgressSurface = domain.EgressSurface
type ProtectionPlan = domain.ProtectionPlan
type Upstream = domain.Upstream
type AuthStrategy = domain.AuthStrategy
type NetworkRoute = domain.NetworkRoute
type IntegrationMode = domain.IntegrationMode
type SurfaceType = domain.SurfaceType
type Protocol = domain.Protocol
type AuthType = domain.AuthType
type NetworkType = domain.NetworkType

const (
	ModeNative  = domain.ModeNative
	ModeManaged = domain.ModeManaged

	SurfaceModelPrimary   = domain.SurfaceModelPrimary
	SurfaceModelAuxiliary = domain.SurfaceModelAuxiliary
	SurfaceModelFallback  = domain.SurfaceModelFallback
	SurfaceVision         = domain.SurfaceVision
	SurfaceEmbedding      = domain.SurfaceEmbedding
	SurfaceImage          = domain.SurfaceImage
	SurfaceAudio          = domain.SurfaceAudio
	SurfaceMCPHTTP        = domain.SurfaceMCPHTTP
	SurfaceMCPStdio       = domain.SurfaceMCPStdio
	SurfaceToolHTTP       = domain.SurfaceToolHTTP
	SurfaceBrowser        = domain.SurfaceBrowser
	SurfaceSubAgent       = domain.SurfaceSubAgent
	SurfaceACP            = domain.SurfaceACP
	SurfaceUnknown        = domain.SurfaceUnknown

	ProtocolOpenAIChat      = domain.ProtocolOpenAIChat
	ProtocolOpenAIResponses = domain.ProtocolOpenAIResponses
	ProtocolAnthropic       = domain.ProtocolAnthropic
	ProtocolGemini          = domain.ProtocolGemini
	ProtocolMCPHTTP         = domain.ProtocolMCPHTTP
	ProtocolMCPStreamable   = domain.ProtocolMCPStreamable
	ProtocolLocalStdio      = domain.ProtocolLocalStdio
	ProtocolUnknown         = domain.ProtocolUnknown

	AuthPassthrough  = domain.AuthPassthrough
	AuthBearer       = domain.AuthBearer
	AuthAnthropicKey = domain.AuthAnthropicKey
	AuthGoogleKey    = domain.AuthGoogleKey
	AuthAWSSigV4     = domain.AuthAWSSigV4
	AuthVertexOAuth  = domain.AuthVertexOAuth
	AuthCustom       = domain.AuthCustom

	NetworkDirect      = domain.NetworkDirect
	NetworkHTTPProxy   = domain.NetworkHTTPProxy
	NetworkSOCKS5      = domain.NetworkSOCKS5
	NetworkSystemProxy = domain.NetworkSystemProxy
)

// Registration is the Core-owned result of a Native/Managed manifest lease.
type Registration struct {
	Manifest   AgentManifest  `json:"manifest"`
	Plan       ProtectionPlan `json:"plan"`
	State      string         `json:"state"`
	Generation uint64         `json:"generation"`
	UpdatedAt  time.Time      `json:"updated_at"`
	ExpiresAt  time.Time      `json:"expires_at,omitempty"`
	ErrorCode  string         `json:"error_code,omitempty"`
}

// Client talks only to one numeric loopback Core endpoint. The management
// token belongs in a trusted host controller and must not be propagated to a
// nested or provider process.
type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

func NewClient(endpoint, managementToken string, transport *http.Client) (*Client, error) {
	normalized, err := validateEndpoint(endpoint)
	if err != nil || !validToken(managementToken) {
		return nil, domain.NewError(domain.ErrInvalidContract, "create native client", "numeric loopback endpoint and bounded management token are required")
	}
	client := http.DefaultClient
	if transport != nil {
		client = transport
	}
	copyClient := *client
	if copyClient.Timeout == 0 || copyClient.Timeout > 30*time.Second {
		copyClient.Timeout = 30 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: normalized, token: managementToken, http: &copyClient}, nil
}

func (c *Client) Register(ctx context.Context, manifest AgentManifest, ttl time.Duration) (Registration, error) {
	if c == nil || ctx == nil || ttl < time.Second || ttl > maxLeaseTTL || ttl%time.Second != 0 {
		return Registration{}, domain.NewError(domain.ErrInvalidContract, "register native integration", "client, context, and bounded lease TTL are required")
	}
	if manifest.Agent.Mode != ModeNative && manifest.Agent.Mode != ModeManaged {
		return Registration{}, domain.NewError(domain.ErrInvalidContract, "register native integration", "agent mode must be native or managed")
	}
	if err := manifest.Validate(); err != nil {
		return Registration{}, err
	}
	var result Registration
	err := c.doJSON(ctx, http.MethodPost, "/v1/agents/leases", map[string]any{"manifest": manifest, "ttl_seconds": int64(ttl / time.Second)}, http.StatusCreated, &result)
	return result, err
}

func (c *Client) Heartbeat(ctx context.Context, agentID string, generation uint64, ttl time.Duration) (Registration, error) {
	if c == nil || ctx == nil || !safeIdentifier(agentID) || generation == 0 || ttl < time.Second || ttl > maxLeaseTTL || ttl%time.Second != 0 {
		return Registration{}, domain.NewError(domain.ErrInvalidContract, "heartbeat native integration", "client, identity, generation, and bounded lease TTL are required")
	}
	var result Registration
	err := c.doJSON(ctx, http.MethodPost, "/v1/agents/"+url.PathEscape(agentID)+"/heartbeat", map[string]any{"generation": generation, "ttl_seconds": int64(ttl / time.Second)}, http.StatusOK, &result)
	return result, err
}

func (c *Client) Remove(ctx context.Context, agentID string, generation uint64) error {
	if c == nil || ctx == nil || !safeIdentifier(agentID) || generation == 0 {
		return domain.NewError(domain.ErrInvalidContract, "remove native integration", "client, identity, and generation are required")
	}
	return c.doJSON(ctx, http.MethodDelete, "/v1/agents/"+url.PathEscape(agentID)+"?generation="+strconv.FormatUint(generation, 10), nil, http.StatusNoContent, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, input any, expectedStatus int, output any) error {
	var body io.Reader
	if input != nil {
		payload, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set(apiVersionHeader, apiVersion)
	request.Header.Set("Accept-Encoding", "identity")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if versions := response.Header.Values(apiVersionHeader); len(versions) != 1 || versions[0] != apiVersion {
		return errors.New("Core returned an incompatible management API version")
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("Core rejected native integration request with status %d", response.StatusCode)
	}
	if output == nil {
		_, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
		return err
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("Core native response has an invalid content type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("Core native response has an invalid content type")
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return errors.New("Core native response uses an unsupported content encoding")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes || jsonsafe.Validate(payload) != nil {
		return errors.New("Core native response is invalid or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("Core native response schema is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Core native response contains trailing data")
	}
	return nil
}

func validateEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("invalid Core endpoint")
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	port, portErr := strconv.ParseUint(parsed.Port(), 10, 16)
	if address == nil || !address.IsLoopback() || portErr != nil || port == 0 {
		return "", errors.New("invalid Core endpoint")
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func validToken(value string) bool {
	if len(value) < minTokenBytes || len(value) > maxTokenBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func safeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}
