package policy

import (
	"net"
	"regexp"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

var (
	policyIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	workspaceRef     = regexp.MustCompile(`^sha256:[a-f0-9]{32}$`)
)

type Scope struct {
	AgentID     string `json:"agent_id,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	Provider    string `json:"provider,omitempty"`
	SurfaceID   string `json:"surface_id,omitempty"`
	FindingType string `json:"finding_type,omitempty"`
}

type Rule struct {
	Scope  Scope         `json:"scope"`
	Action domain.Action `json:"action"`
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

func (s Scope) Validate() error {
	for _, value := range []string{s.AgentID, s.SurfaceID, s.FindingType} {
		if value != "" && !policyIdentifier.MatchString(value) {
			return domain.NewError(domain.ErrInvalidContract, "validate policy scope", "identifier is invalid")
		}
	}
	if s.Workspace != "" && !workspaceRef.MatchString(s.Workspace) {
		return domain.NewError(domain.ErrInvalidContract, "validate policy scope", "workspace must be a hashed reference")
	}
	if s.Provider != "" && !validProvider(s.Provider) {
		return domain.NewError(domain.ErrInvalidContract, "validate policy scope", "provider host is invalid")
	}
	return nil
}

func (e Engine) Decide(context Scope, interactive bool) (Decision, error) {
	if !e.Default.Valid() {
		return Decision{}, domain.NewError(domain.ErrInvalidContract, "evaluate policy", "default action is invalid")
	}
	if err := context.Validate(); err != nil {
		return Decision{}, err
	}
	if err := validateRules(e.Rules); err != nil {
		return Decision{}, err
	}
	decision := Decision{Action: e.Default, Reason: "default policy"}
	bestSpecificity := -1
	explicitBlock := false
	for i := range e.Rules {
		rule := &e.Rules[i]
		specificity, matches := match(rule.Scope, context)
		if !matches {
			continue
		}
		// An explicit block is never downgraded by another matching rule.
		if rule.Action == domain.ActionBlock {
			if !explicitBlock || specificity > bestSpecificity {
				decision = Decision{Action: domain.ActionBlock, Rule: rule, Reason: "explicit matching block rule"}
				bestSpecificity = specificity
			}
			explicitBlock = true
			continue
		}
		if !explicitBlock && specificity > bestSpecificity {
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

func validateRules(rules []Rule) error {
	seen := make(map[Scope]struct{}, len(rules))
	for _, rule := range rules {
		if !rule.Action.Valid() || rule.Scope.Validate() != nil {
			return domain.NewError(domain.ErrInvalidContract, "evaluate policy", "rule action or scope is invalid")
		}
		if _, duplicate := seen[rule.Scope]; duplicate {
			return domain.NewError(domain.ErrInvalidContract, "evaluate policy", "duplicate policy scope is ambiguous")
		}
		seen[rule.Scope] = struct{}{}
	}
	return nil
}

func validProvider(value string) bool {
	if len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func match(rule, context Scope) (int, bool) {
	specificity := 0
	pairs := []struct {
		rule, context string
		weight        int
	}{
		{rule.AgentID, context.AgentID, 1},
		{rule.Workspace, context.Workspace, 2},
		{rule.Provider, context.Provider, 4},
		{rule.SurfaceID, context.SurfaceID, 8},
		{rule.FindingType, context.FindingType, 16},
	}
	for _, pair := range pairs {
		if pair.rule == "" {
			continue
		}
		if pair.rule != pair.context {
			return 0, false
		}
		specificity += pair.weight
	}
	return specificity, true
}
