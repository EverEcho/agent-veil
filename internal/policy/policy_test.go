package policy

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestExplicitBlockCannotBeDowngraded(t *testing.T) {
	engine := Engine{Default: domain.ActionRedact, Rules: []Rule{
		{Scope: Scope{AgentID: "codex"}, Action: domain.ActionBlock},
		{Scope: Scope{AgentID: "codex", SurfaceID: "primary", FindingType: "secret.github_pat"}, Action: domain.ActionAllow},
	}}
	decision, err := engine.Decide(Scope{AgentID: "codex", SurfaceID: "primary", FindingType: "secret.github_pat"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != domain.ActionBlock {
		t.Fatalf("specific allow downgraded explicit block: %+v", decision)
	}
}

func TestAskFailsClosedWhenNonInteractive(t *testing.T) {
	decision, err := (Engine{Default: domain.ActionAsk}).Decide(Scope{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != domain.ActionBlock {
		t.Fatalf("ASK did not fail closed: %+v", decision)
	}
}
