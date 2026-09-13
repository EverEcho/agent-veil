package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"gopkg.in/yaml.v3"
)

// HermesRouteBinding is the short-lived capability assigned to one discovered
// Hermes egress surface. Bindings are keyed by surface ID when passed to
// RewriteHermesConfig.
type HermesRouteBinding struct {
	RouteID string
	Token   string
}

type hermesRewriteTarget struct {
	id       string
	protocol domain.Protocol
	node     *yaml.Node
	mcp      bool
}

var hermesRouteIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// RewriteHermesConfig returns an isolated launch configuration in which every
// discovered network surface points at its own authenticated Core route. It
// preserves the original provider name and credentials so Hermes can continue
// to resolve OAuth and provider-specific credential pools; route capabilities
// are attached through temporary provider entries matched by the rewritten
// base URL.
func RewriteHermesConfig(content []byte, coreEndpoint, sessionID string, bindings map[string]HermesRouteBinding) ([]byte, error) {
	if len(content) == 0 || len(content) > maxHermesConfigBytes {
		return nil, hermesRewriteError("configuration is empty or too large")
	}
	if err := validateCoreEndpoint(coreEndpoint); err != nil {
		return nil, hermesRewriteError("Core endpoint is invalid")
	}
	if !validCapabilityID(sessionID) {
		return nil, hermesRewriteError("session identity is invalid")
	}

	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&document); err != nil {
		return nil, hermesRewriteError("configuration is invalid YAML")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, hermesRewriteError("configuration contains multiple YAML documents")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, hermesRewriteError("configuration root must be a mapping")
	}
	if err := validateHermesYAMLNode(document.Content[0]); err != nil {
		return nil, err
	}

	slots, _, err := ParseHermesConfig(content)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]Slot, len(slots))
	for _, slot := range slots {
		if slot.BaseURL == "" || hermesTransport(slot.Protocol) == "" || !slot.Rewritable {
			return nil, hermesRewriteError("every network surface must use a verified rewritable runtime")
		}
		if _, duplicate := byID[slot.ID]; duplicate {
			return nil, hermesRewriteError("discovered surface IDs must be unique")
		}
		byID[slot.ID] = slot
	}

	var decoded hermesConfig
	if err := document.Content[0].Decode(&decoded); err != nil {
		return nil, hermesRewriteError("configuration shape is invalid")
	}
	targets, err := collectHermesRewriteTargets(document.Content[0], decoded, byID)
	if err != nil {
		return nil, err
	}
	if len(targets) != len(slots) || len(bindings) != len(slots) {
		return nil, hermesRewriteError("route bindings do not exactly cover discovered network surfaces")
	}
	seenRoutes := make(map[string]struct{}, len(bindings))
	seenTokens := make(map[string]struct{}, len(bindings))
	for _, target := range targets {
		binding, ok := bindings[target.id]
		if !ok || !hermesRouteIDPattern.MatchString(binding.RouteID) || !validRouteToken(binding.Token) {
			return nil, hermesRewriteError("route binding is missing or invalid")
		}
		if _, duplicate := seenRoutes[binding.RouteID]; duplicate {
			return nil, hermesRewriteError("route binding IDs must be unique")
		}
		if _, duplicate := seenTokens[binding.Token]; duplicate {
			return nil, hermesRewriteError("route binding tokens must be unique")
		}
		seenRoutes[binding.RouteID] = struct{}{}
		seenTokens[binding.Token] = struct{}{}
	}

	root := document.Content[0]
	for _, target := range targets {
		binding := bindings[target.id]
		baseURL := hermesProtectedBaseURL(coreEndpoint, binding.RouteID, target.protocol, target.mcp, sessionID, binding.Token)
		if target.mcp {
			setHermesScalar(target.node, "url", baseURL)
			headers, headerErr := ensureHermesMapping(target.node, "headers")
			if headerErr != nil {
				return nil, headerErr
			}
			setHermesScalar(headers, "X-Veil-Session", sessionID)
			setHermesScalar(headers, "X-Veil-Route-Token", binding.Token)
			continue
		}
		if target.id != "primary" {
			// Hermes 0.20.6 auxiliary Codex clients otherwise use a fixed
			// upstream constant and ignore their configured base_url. A custom
			// route keeps the Responses adapter while inheriting the primary
			// runtime token for the same loopback host.
			setHermesScalar(target.node, "provider", "custom")
		} else if provider := hermesMappingValue(target.node, "provider"); provider != nil {
			resolvedProvider := strings.TrimSpace(byID[target.id].Metadata["provider"])
			if resolvedProvider != "" && !strings.EqualFold(strings.TrimSpace(provider.Value), resolvedProvider) {
				setHermesScalar(target.node, "provider", resolvedProvider)
			}
		}
		setHermesScalar(target.node, "base_url", baseURL)
		setHermesScalar(target.node, "api_mode", hermesTransport(target.protocol))
	}

	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return nil, hermesRewriteError("rewritten configuration could not be encoded")
	}
	if err := encoder.Close(); err != nil {
		return nil, hermesRewriteError("rewritten configuration could not be finalized")
	}
	if output.Len() == 0 || output.Len() > maxHermesConfigBytes {
		return nil, hermesRewriteError("rewritten configuration exceeds its size limit")
	}
	rewrittenSlots, _, err := ParseHermesConfig(output.Bytes())
	if err != nil || len(rewrittenSlots) != len(slots) {
		return nil, hermesRewriteError("rewritten configuration failed validation")
	}
	for _, slot := range rewrittenSlots {
		binding, ok := bindings[slot.ID]
		if !ok || slot.Protocol != byID[slot.ID].Protocol || slot.BaseURL != hermesProtectedBaseURL(coreEndpoint, binding.RouteID, slot.Protocol, slot.Type == domain.SurfaceMCPHTTP, sessionID, binding.Token) {
			return nil, hermesRewriteError("rewritten route does not match its protected binding: " + slot.ID)
		}
	}
	return output.Bytes(), nil
}

func collectHermesRewriteTargets(root *yaml.Node, config hermesConfig, slots map[string]Slot) ([]hermesRewriteTarget, error) {
	targets := make([]hermesRewriteTarget, 0, len(slots))
	add := func(id string, node *yaml.Node, mcp bool) error {
		slot, ok := slots[id]
		if !ok || node == nil || node.Kind != yaml.MappingNode {
			return hermesRewriteError("configuration routes do not match discovered surfaces")
		}
		targets = append(targets, hermesRewriteTarget{id: id, protocol: slot.Protocol, node: node, mcp: mcp})
		return nil
	}
	if err := add("primary", hermesMappingValue(root, "model"), false); err != nil {
		return nil, err
	}

	index := 1
	for _, key := range []string{"fallback_providers", "fallback_model"} {
		node := hermesMappingValue(root, key)
		if node == nil {
			continue
		}
		entries, err := hermesRouteNodes(node)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if err := add(fmt.Sprintf("fallback-%d", index), entry, false); err != nil {
				return nil, err
			}
			index++
		}
	}

	auxiliary := hermesMappingValue(root, "auxiliary")
	auxNames := make([]string, 0, len(config.Auxiliary))
	for name := range config.Auxiliary {
		auxNames = append(auxNames, name)
	}
	sort.Strings(auxNames)
	for _, name := range auxNames {
		node := hermesMappingValue(auxiliary, name)
		prefix := "aux-" + strings.ReplaceAll(name, "_", "-")
		if err := add(prefix, node, false); err != nil {
			return nil, err
		}
		fallbackIndex := 1
		for _, key := range []string{"fallback_chain", "fallback_providers"} {
			entries, err := hermesRouteNodes(hermesMappingValue(node, key))
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if err := add(fmt.Sprintf("%s-fallback-%d", prefix, fallbackIndex), entry, false); err != nil {
					return nil, err
				}
				fallbackIndex++
			}
		}
	}

	if configuredHermesRoute(config.Delegation) {
		node := hermesMappingValue(root, "delegation")
		if err := add("delegation", node, false); err != nil {
			return nil, err
		}
		entries, err := hermesRouteNodes(hermesMappingValue(node, "fallback_providers"))
		if err != nil {
			return nil, err
		}
		for fallbackIndex, entry := range entries {
			if err := add(fmt.Sprintf("delegation-fallback-%d", fallbackIndex+1), entry, false); err != nil {
				return nil, err
			}
		}
	}

	mcp := hermesMappingValue(root, "mcp_servers")
	mcpNames := make([]string, 0, len(config.MCPServers))
	for name := range config.MCPServers {
		mcpNames = append(mcpNames, name)
	}
	sort.Strings(mcpNames)
	for _, name := range mcpNames {
		server := config.MCPServers[name]
		if server.Enabled != nil && !*server.Enabled || strings.TrimSpace(server.Command) != "" {
			continue
		}
		id := "mcp-" + strings.ReplaceAll(name, "_", "-")
		if err := add(id, hermesMappingValue(mcp, name), true); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func hermesRouteNodes(node *yaml.Node) ([]*yaml.Node, error) {
	if node == nil || node.Tag == "!!null" {
		return nil, nil
	}
	switch node.Kind {
	case yaml.MappingNode:
		return []*yaml.Node{node}, nil
	case yaml.SequenceNode:
		result := make([]*yaml.Node, 0, len(node.Content))
		for _, entry := range node.Content {
			if entry.Kind != yaml.MappingNode {
				return nil, hermesRewriteError("route list contains a non-mapping entry")
			}
			result = append(result, entry)
		}
		return result, nil
	default:
		return nil, hermesRewriteError("route list has an unsupported shape")
	}
}

func validateHermesYAMLNode(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return hermesRewriteError("YAML aliases and anchors are not allowed for protected launch")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return hermesRewriteError("mapping keys must be strings")
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return hermesRewriteError("duplicate YAML mapping key")
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateHermesYAMLNode(child); err != nil {
			return err
		}
	}
	return nil
}

func hermesProtectedBaseURL(endpoint, routeID string, protocol domain.Protocol, mcp bool, sessionID, routeToken string) string {
	base := strings.TrimSuffix(endpoint, "/") + "/route/" + routeID
	if mcp {
		return base + "/mcp"
	}
	base += "/__veil/" + url.PathEscape(veilproxy.EncodeCapability(sessionID, routeToken))
	if protocol == domain.ProtocolOpenAIChat || protocol == domain.ProtocolOpenAIResponses {
		return base + "/v1"
	}
	return base
}

func hermesTransport(protocol domain.Protocol) string {
	switch protocol {
	case domain.ProtocolOpenAIChat:
		return "chat_completions"
	case domain.ProtocolOpenAIResponses:
		return "codex_responses"
	case domain.ProtocolAnthropic:
		return "anthropic_messages"
	case domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable:
		return "mcp"
	default:
		return ""
	}
}

func ensureHermesMapping(parent *yaml.Node, key string) (*yaml.Node, error) {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil, hermesRewriteError("configuration section is not a mapping")
	}
	node := hermesMappingValue(parent, key)
	if node == nil {
		node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setHermesNode(parent, key, node)
	}
	if node.Kind != yaml.MappingNode {
		return nil, hermesRewriteError("configuration section is not a mapping")
	}
	return node, nil
}

func hermesMappingValue(parent *yaml.Node, key string) *yaml.Node {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(parent.Content); index += 2 {
		if parent.Content[index].Value == key {
			return parent.Content[index+1]
		}
	}
	return nil
}

func setHermesScalar(parent *yaml.Node, key, value string) {
	setHermesNode(parent, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func setHermesBool(parent *yaml.Node, key string, value bool) {
	text := "false"
	if value {
		text = "true"
	}
	setHermesNode(parent, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: text})
}

func setHermesNode(parent *yaml.Node, key string, value *yaml.Node) {
	for index := 0; index+1 < len(parent.Content); index += 2 {
		if parent.Content[index].Value == key {
			parent.Content[index+1] = value
			return
		}
	}
	parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func hermesMapping(values ...string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for index := 0; index+1 < len(values); index += 2 {
		setHermesScalar(node, values[index], values[index+1])
	}
	return node
}

func hermesRewriteError(detail string) error {
	return domain.NewError(domain.ErrInvalidContract, "rewrite hermes config", detail)
}
