package routing

import "testing"

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
