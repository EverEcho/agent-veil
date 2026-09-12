package routing

import (
	"strings"
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

func TestRoutingGraphBoundsNodesAndText(t *testing.T) {
	valid := Graph{Nodes: []Node{{"a", "Agent", NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"p", "Provider", NodeProvider}}}
	invalidUTF8 := string([]byte{0xff})
	for _, graph := range []Graph{
		{Nodes: append(append([]Node(nil), valid.Nodes...), make([]Node, MaxGraphNodes-2)...)},
		{Nodes: []Node{{"not safe", "Agent", NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"p", "Provider", NodeProvider}}},
		{Nodes: []Node{{"a", strings.Repeat("n", maxNodeNameBytes+1), NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"p", "Provider", NodeProvider}}},
		{Nodes: []Node{{"a", invalidUTF8, NodeAgent}, {"v", "AgentVeil", NodeDLP}, {"p", "Provider", NodeProvider}}},
	} {
		if err := graph.ValidateStructure(); err == nil {
			t.Fatalf("unbounded or malformed graph accepted: %+v", graph)
		}
	}
}

func TestRoutingRisksBoundsUnvalidatedInput(t *testing.T) {
	nodes := make([]Node, MaxGraphNodes+100)
	for index := range nodes {
		nodes[index] = Node{ID: "n", Name: "Modifier", Kind: NodeContentModifier}
	}
	nodes[0] = Node{ID: "v", Name: "AgentVeil", Kind: NodeDLP}
	if risks := (Graph{Nodes: nodes}).Risks("primary"); len(risks) != MaxGraphNodes-1 {
		t.Fatalf("risk scan was not bounded: got %d risks", len(risks))
	}
}
