package detector

import (
	"regexp"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const (
	MaxRulePackRules   = 256
	MaxRulePatternSize = 2 << 10
)

var ruleIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type RuleDefinition struct {
	ID              string          `json:"id"`
	Category        string          `json:"category"`
	Severity        domain.Severity `json:"severity"`
	SuggestedAction domain.Action   `json:"suggested_action"`
	Pattern         string          `json:"pattern"`
	CaptureGroup    int             `json:"capture_group,omitempty"`
}

type RulePack struct {
	SchemaVersion string           `json:"schema_version"`
	Rules         []RuleDefinition `json:"rules"`
}

func NewDefaultWithRulePack(pack RulePack) (*Scanner, error) {
	if pack.SchemaVersion != "v1" || len(pack.Rules) == 0 || len(pack.Rules) > MaxRulePackRules {
		return nil, domain.NewError(domain.ErrInvalidContract, "compile rule pack", "rule pack schema or size is invalid")
	}
	scanner := NewDefault()
	known := make(map[string]struct{}, len(scanner.rules)+len(pack.Rules))
	for _, builtIn := range scanner.rules {
		known[builtIn.id] = struct{}{}
	}
	scanner.packRuleIDs = make(map[string]struct{}, len(pack.Rules))
	for _, definition := range pack.Rules {
		if !validRuleIdentifier(definition.ID) || !validRuleIdentifier(definition.Category) || !definition.Severity.Valid() || !definition.SuggestedAction.Valid() || definition.Pattern == "" || len(definition.Pattern) > MaxRulePatternSize || definition.CaptureGroup < 0 {
			return nil, domain.NewError(domain.ErrInvalidContract, "compile rule pack", "rule definition is invalid")
		}
		if _, duplicate := known[definition.ID]; duplicate {
			return nil, domain.NewError(domain.ErrInvalidContract, "compile rule pack", "rule id is duplicated or shadows a built-in rule")
		}
		compiled, err := regexp.Compile(definition.Pattern)
		if err != nil || definition.CaptureGroup > compiled.NumSubexp() || matchesEmpty(compiled) {
			return nil, domain.NewError(domain.ErrInvalidContract, "compile rule pack", "rule pattern or capture group is invalid")
		}
		known[definition.ID] = struct{}{}
		scanner.packRuleIDs[definition.ID] = struct{}{}
		scanner.rules = append(scanner.rules, rule{id: definition.ID, category: definition.Category, severity: definition.Severity, action: definition.SuggestedAction, pattern: compiled, group: definition.CaptureGroup})
	}
	return scanner, nil
}

func validRuleIdentifier(value string) bool {
	return ruleIdentifierPattern.MatchString(value) && !strings.Contains(value, "..")
}

func matchesEmpty(pattern *regexp.Regexp) bool {
	for _, sample := range []string{"", "x", " ", "\n"} {
		if location := pattern.FindStringIndex(sample); location != nil && location[0] == location[1] {
			return true
		}
	}
	return false
}
