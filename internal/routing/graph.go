package routing

import (
	"regexp"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/domain"
)

const (
	MaxGraphNodes    = 256
	maxNodeNameBytes = 256
)

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type NodeKind string

const (
	NodeAgent           NodeKind = "agent"
	NodeContentModifier NodeKind = "content_modifier"
	NodeDLP             NodeKind = "dlp"
	NodeTransport       NodeKind = "network_transport"
	NodeProvider        NodeKind = "provider"
)

type Node struct {
	ID, Name string
	Kind     NodeKind
}
type Graph struct{ Nodes []Node }

func (kind NodeKind) Valid() bool {
	switch kind {
	case NodeAgent, NodeContentModifier, NodeDLP, NodeTransport, NodeProvider:
		return true
	default:
		return false
	}
}

func (g Graph) Risks(surfaceID string) []domain.ProtectionRisk {
	dlpSeen := false
	var risks []domain.ProtectionRisk
	nodes := g.Nodes
	if len(nodes) > MaxGraphNodes {
		nodes = nodes[:MaxGraphNodes]
	}
	for _, node := range nodes {
		if node.Kind == NodeDLP {
			dlpSeen = true
		}
		if dlpSeen && node.Kind == NodeContentModifier {
			risks = append(risks, domain.ProtectionRisk{SurfaceID: surfaceID, Code: domain.RiskContentModifierAfterDLP, Severity: domain.SeverityCritical, Message: "content-modifying middleware appears after AgentVeil"})
		}
	}
	return risks
}

func (g Graph) Validate() error {
	if err := g.ValidateStructure(); err != nil {
		return err
	}
	if len(g.Risks("")) > 0 {
		return domain.NewError(domain.ErrPolicyBlocked, "validate routing graph", "content modifier after DLP")
	}
	return nil
}

// ValidateStructure checks graph shape independently from policy ordering so a
// malformed graph cannot be downgraded into a reportable routing risk.
func (g Graph) ValidateStructure() error {
	if len(g.Nodes) < 3 || len(g.Nodes) > MaxGraphNodes {
		return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "node count must be within its configured bounds")
	}
	if g.Nodes[0].Kind != NodeAgent || g.Nodes[len(g.Nodes)-1].Kind != NodeProvider {
		return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "graph must run from agent to provider")
	}
	dlp := 0
	ids := map[string]struct{}{}
	for index, node := range g.Nodes {
		if !nodeIDPattern.MatchString(node.ID) || node.Name == "" || len(node.Name) > maxNodeNameBytes || !utf8.ValidString(node.Name) || !node.Kind.Valid() {
			return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "node id, name, and kind are required")
		}
		if _, ok := ids[node.ID]; ok {
			return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "duplicate node id")
		}
		ids[node.ID] = struct{}{}
		if node.Kind == NodeDLP {
			dlp++
		}
		if index > 0 && node.Kind == NodeAgent {
			return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "agent can only be the first node")
		}
		if index < len(g.Nodes)-1 && node.Kind == NodeProvider {
			return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "provider can only be the last node")
		}
	}
	if dlp != 1 {
		return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "exactly one DLP checkpoint is required")
	}
	return nil
}
