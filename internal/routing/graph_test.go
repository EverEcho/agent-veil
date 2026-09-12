package routing

import (
	"testing"
)

func TestContentModifierAfterDLPIsBlocked(t *testing.T) {
	good := Graph{Nodes: []Node{{"a", "Agent", NodeAgent}, {"m", "Enhancer", NodeContentModifier}, {"v", "AgentVeil", NodeDLP}, {"n", "Clash", NodeTransport}, {"p", "Provider", NodeProvider}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := Graph{Nodes: []Node{{"a", "Agent", NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"m", "Enhancer", NodeContentModifier}, {"p", "Provider", NodeProvider}}}
	if err := bad.Validate(); err == nil || len(bad.Risks("primary")) != 1 {
		t.Fatal("modifier after DLP was accepted")
	}
}

func TestRoutingGraphRejectsUnknownKindsAndMisplacedEndpoints(t *testing.T) {
	for _, graph := range []Graph{
		{Nodes: []Node{{"a", "Agent", NodeAgent}, {"x", "Mystery", NodeKind("mystery")}, {"v", "AgentVeil", NodeDLP}, {"p", "Provider", NodeProvider}}},
		{Nodes: []Node{{"a", "Agent", NodeAgent}, {"p", "Provider", NodeProvider}, {"v", "AgentVeil", NodeDLP}, {"z", "Provider", NodeProvider}}},
		{Nodes: []Node{{"a", "Agent", NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"a2", "Agent", NodeAgent}, {"p", "Provider", NodeProvider}}},
		{Nodes: []Node{{"a", "", NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"p", "Provider", NodeProvider}}},
	} {
		if err := graph.Validate(); err == nil {
			t.Fatalf("invalid graph accepted: %+v", graph)
		}
	}
}
