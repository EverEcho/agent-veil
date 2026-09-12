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
	decision := Decision{Action: e.Default, Reason: "default policy"}
	bestSpecificity := -1
	for i := range e.Rules {
		rule := &e.Rules[i]
		if !rule.Action.Valid() || rule.Scope.Validate() != nil {
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
