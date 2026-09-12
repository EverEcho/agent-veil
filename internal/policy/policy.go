package policy

import (
	"github.com/agentveil/agentveil/internal/domain"
)

type Scope struct {
	AgentID     string
	Workspace   string
	Provider    string
	SurfaceID   string
	FindingType string
}

type Rule struct {
	Scope  Scope
	Action domain.Action
}

type Decision struct {
	Action domain.Action
	Rule   *Rule
	Reason string
}

type Engine struct {
	Default domain.Action
	Rules   []Rule
}

func (e Engine) Decide(context Scope, interactive bool) (Decision, error) {
	if !e.Default.Valid() {
		return Decision{}, domain.NewError(domain.ErrInvalidContract, "evaluate policy", "default action is invalid")
	}
	decision := Decision{Action: e.Default, Reason: "default policy"}
	bestSpecificity := -1
	for i := range e.Rules {
		rule := &e.Rules[i]
		if !rule.Action.Valid() {
			return Decision{}, domain.NewError(domain.ErrInvalidContract, "evaluate policy", "rule action is invalid")
		}
		specificity, matches := match(rule.Scope, context)
		if !matches {
			continue
		}
		// An explicit block is never downgraded by another matching rule.
		if rule.Action == domain.ActionBlock {
			decision = Decision{Action: domain.ActionBlock, Rule: rule, Reason: "explicit matching block rule"}
			bestSpecificity = specificity
			continue
		}
		if decision.Action != domain.ActionBlock && specificity >= bestSpecificity {
			decision = Decision{Action: rule.Action, Rule: rule, Reason: "most specific matching rule"}
			bestSpecificity = specificity
		}
	}
	if decision.Action == domain.ActionAsk && !interactive {
		decision.Action = domain.ActionBlock
		decision.Reason = "ASK fails closed in a non-interactive context"
	}
	return decision, nil
}

func match(rule, context Scope) (int, bool) {
	specificity := 0
	pairs := [][2]string{{rule.AgentID, context.AgentID}, {rule.Workspace, context.Workspace},
		{rule.Provider, context.Provider}, {rule.SurfaceID, context.SurfaceID}, {rule.FindingType, context.FindingType}}
	for _, pair := range pairs {
		if pair[0] == "" {
			continue
		}
		if pair[0] != pair[1] {
			return 0, false
		}
		specificity++
	}
	return specificity, true
}
