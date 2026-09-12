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

func TestPolicyUsesDocumentedLayerPrecedence(t *testing.T) {
	engine := Engine{Default: domain.ActionBlock, Rules: []Rule{
		{Scope: Scope{AgentID: "codex", Workspace: "sha256:0123456789abcdef0123456789abcdef"}, Action: domain.ActionRedact},
		{Scope: Scope{FindingType: "pii.email"}, Action: domain.ActionAllow},
	}}
	decision, err := engine.Decide(Scope{AgentID: "codex", Workspace: "sha256:0123456789abcdef0123456789abcdef", FindingType: "pii.email"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != domain.ActionAllow || decision.Rule == nil || decision.Rule.Scope.FindingType != "pii.email" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestPolicyRejectsDuplicateScopes(t *testing.T) {
	engine := Engine{Default: domain.ActionRedact, Rules: []Rule{
		{Scope: Scope{AgentID: "codex"}, Action: domain.ActionAllow},
		{Scope: Scope{AgentID: "codex"}, Action: domain.ActionAsk},
	}}
	if _, err := engine.Decide(Scope{AgentID: "codex"}, true); err == nil {
		t.Fatal("ambiguous duplicate policy scope was accepted")
	}
}

func TestPolicyScopeRejectsSensitiveOrMalformedPersistence(t *testing.T) {
	valid := Scope{AgentID: "codex", Workspace: "sha256:0123456789abcdef0123456789abcdef", Provider: "api.example.com", SurfaceID: "primary", FindingType: "pii.email"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []Scope{
		{AgentID: "dev@example.com"},
		{Workspace: "/home/alice/private-project"},
		{Provider: "api.example.com/path"},
		{FindingType: "secret value"},
	} {
		if err := scope.Validate(); err == nil {
			t.Fatalf("unsafe scope accepted: %+v", scope)
		}
	}
	if _, err := (Engine{Default: domain.ActionRedact}).Decide(Scope{Workspace: "/raw/path"}, true); err == nil {
		t.Fatal("unsafe runtime context accepted")
	}
}
