package detector

import (
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestRulePackAddsBoundedAttributedRules(t *testing.T) {
	pack := RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{
		ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh,
		SuggestedAction: domain.ActionRedact, Pattern: `TICKET-([0-9]{6})`, CaptureGroup: 1,
	}}}
	scanner, err := NewDefaultWithRulePack(pack)
	if err != nil {
		t.Fatal(err)
	}
	matches := scan(t, scanner, "reference TICKET-123456")
	if len(matches) != 1 || matches[0].Value != "123456" || matches[0].Finding.RuleID != "custom.ticket" || matches[0].Finding.Detector != "rule_pack" {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestRulePackRejectsUnsafeAndAmbiguousDefinitions(t *testing.T) {
	valid := RuleDefinition{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}
	for _, test := range []struct {
		name string
		pack RulePack
	}{
		{"schema", RulePack{SchemaVersion: "v2", Rules: []RuleDefinition{valid}}},
		{"empty", RulePack{SchemaVersion: "v1"}},
		{"builtin-shadow", RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{ID: "pii.email", Category: "custom.email", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `x+`}}}},
		{"duplicate", RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{valid, valid}}},
		{"invalid-regexp", RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{ID: "custom.bad", Category: "custom.bad", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `(`}}}},
		{"empty-match", RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{ID: "custom.empty", Category: "custom.empty", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `a*`}}}},
		{"capture", RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{ID: "custom.capture", Category: "custom.capture", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `(x)`, CaptureGroup: 2}}}},
		{"oversized-pattern", RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{ID: "custom.large", Category: "custom.large", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: strings.Repeat("x", MaxRulePatternSize+1)}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewDefaultWithRulePack(test.pack); err == nil {
				t.Fatal("unsafe rule pack was accepted")
			}
		})
	}
}

func TestOptionalCaptureGroupDoesNotPanicScanner(t *testing.T) {
	pack := RulePack{SchemaVersion: "v1", Rules: []RuleDefinition{{ID: "custom.optional", Category: "custom.optional", Severity: domain.SeverityMedium, SuggestedAction: domain.ActionRedact, Pattern: `(secret)?safe`, CaptureGroup: 1}}}
	scanner, err := NewDefaultWithRulePack(pack)
	if err != nil {
		t.Fatal(err)
	}
	if matches := scan(t, scanner, "safe"); len(matches) != 0 {
		t.Fatalf("unmatched optional capture produced a finding: %+v", matches)
	}
}
