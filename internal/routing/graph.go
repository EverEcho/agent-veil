package routing

import "github.com/agentveil/agentveil/internal/domain"

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

func (g Graph) Risks(surfaceID string) []domain.ProtectionRisk {
	dlpSeen := false
	var risks []domain.ProtectionRisk
	for _, node := range g.Nodes {
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
	if len(g.Nodes) < 3 || g.Nodes[0].Kind != NodeAgent || g.Nodes[len(g.Nodes)-1].Kind != NodeProvider {
		return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "graph must run from agent to provider")
	}
	dlp := 0
	ids := map[string]struct{}{}
	for _, node := range g.Nodes {
		if node.ID == "" {
			return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "node id is required")
		}
		if _, ok := ids[node.ID]; ok {
			return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "duplicate node id")
		}
		ids[node.ID] = struct{}{}
		if node.Kind == NodeDLP {
			dlp++
		}
	}
	if dlp != 1 {
		return domain.NewError(domain.ErrInvalidContract, "validate routing graph", "exactly one DLP checkpoint is required")
	}
	if len(g.Risks("")) > 0 {
		return domain.NewError(domain.ErrPolicyBlocked, "validate routing graph", "content modifier after DLP")
	}
	return nil
}
