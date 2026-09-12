package detector

import (
	"errors"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

type wrongPathSemantic struct{}

func (wrongPathSemantic) Detect(string, string) ([]domain.Finding, error) {
	return []domain.Finding{{RuleID: "pii.semantic_name", Category: "pii.semantic_name", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: "/other", Start: 0, End: 1}, Confidence: 0.8, Detector: "semantic", SuggestedAction: domain.ActionRedact}}, nil
}

func TestValidatedPIIAndSecrets(t *testing.T) {
	s := NewDefault()
	matches := scan(t, s, "mail dev@example.com phone 13800138000 id 11010519491231002X card 4111111111111111 ghp_abcdefghijklmnopqrstuvwxyz")
	if len(matches) != 5 {
		t.Fatalf("matches=%+v", matches)
	}
	if got := scan(t, s, "invalid card 4111111111111112 invalid id 110105194912310021"); len(got) != 0 {
		t.Fatalf("validators accepted invalid values: %+v", got)
	}
}

func TestMergeProtectsEntireOverlappingUnion(t *testing.T) {
	tests := []struct {
		name    string
		matches []Match
		winner  string
	}{
		{"later-secret-wins", []Match{
			{Finding: domain.Finding{Category: "pii.generic", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: "/x", Start: 0, End: 6}}, Value: "abcdef"},
			{Finding: domain.Finding{Category: "secret.token", Severity: domain.SeverityCritical, Location: domain.ContentLocation{Path: "/x", Start: 4, End: 10}}, Value: "efghij"},
		}, "secret.token"},
		{"earlier-high-severity-wins", []Match{
			{Finding: domain.Finding{Category: "pii.critical", Severity: domain.SeverityCritical, Location: domain.ContentLocation{Path: "/x", Start: 0, End: 6}}, Value: "abcdef"},
			{Finding: domain.Finding{Category: "pii.medium", Severity: domain.SeverityMedium, Location: domain.ContentLocation{Path: "/x", Start: 4, End: 10}}, Value: "efghij"},
		}, "pii.critical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			merged := Merge(test.matches)
			if len(merged) != 1 || merged[0].Finding.Category != test.winner || merged[0].Finding.Location.Start != 0 || merged[0].Finding.Location.End != 10 || merged[0].Value != "abcdefghij" {
				t.Fatalf("merged=%+v", merged)
			}
		})
	}
}

func TestSemanticDetectorCannotReturnAnotherFieldPath(t *testing.T) {
	_, err := NewDefault().WithSemantic(wrongPathSemantic{}, true).ScanChecked("/input", "safe")
	var veil *domain.VeilError
	if !errors.As(err, &veil) || veil.Code != domain.ErrDetectorFailure {
		t.Fatalf("error=%v", err)
	}
}

func TestCaptureGroupPreservesAssignmentContext(t *testing.T) {
	matches := scan(t, NewDefault(), "Authorization stays; API_KEY=Abcdef123456!xyz")
	if len(matches) != 1 || matches[0].Value != "Abcdef123456!xyz" {
		t.Fatalf("capture=%+v", matches)
	}
}

func TestContextualSecretsPreserveSyntax(t *testing.T) {
	text := `Authorization: Bearer Abcdefghijklmnop123456 export OPENAI_API_KEY="sk-examplevalue1234567890" AWS_SECRET_ACCESS_KEY='AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=='`
	matches := scan(t, NewDefault(), text)
	values := map[string]string{}
	for _, match := range matches {
		values[match.Finding.Category] = match.Value
	}
	for category, want := range map[string]string{
		"secret.bearer":         "Abcdefghijklmnop123456",
		"secret.openai_key":     "sk-examplevalue1234567890",
		"secret.aws_secret_key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==",
	} {
		if got := values[category]; got != want {
			t.Fatalf("category %s value=%q want=%q matches=%+v", category, got, want, matches)
		}
	}
	if len(matches) != 3 {
		t.Fatalf("unexpected contextual matches: %+v", matches)
	}
}

func TestCaseInsensitiveBearerPrefixRemainsDetectable(t *testing.T) {
	matches := scan(t, NewDefault(), "authorization: bEaReR Abcdefghijklmnop123456")
	if len(matches) != 1 || matches[0].Finding.Category != "secret.bearer" || matches[0].Value != "Abcdefghijklmnop123456" {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestEncryptedAndDSAPrivateKeysAreBlocked(t *testing.T) {
	for _, marker := range []string{"-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----"} {
		matches := scan(t, NewDefault(), marker)
		if len(matches) != 1 || matches[0].Finding.Category != "secret.private_key" || matches[0].Finding.SuggestedAction != "block" {
			t.Fatalf("marker %q matches=%+v", marker, matches)
		}
	}
}

func TestFeatureAndPrefixPrefilterSkipsImpossibleRegexes(t *testing.T) {
	scanner := NewDefault()
	text := "ordinary prose without structured identifiers"
	features := scanFeatures(text)
	prefixCandidates := scanner.scanPrefixCandidates(text)
	candidates := 0
	for _, rule := range scanner.rules {
		if scanner.isCandidate(rule, features, prefixCandidates) {
			candidates++
		}
	}
	if candidates >= len(scanner.rules)/2 {
		t.Fatalf("prefilter retained %d of %d rules", candidates, len(scanner.rules))
	}
	if matches := scan(t, scanner, "ghp_abcdefghijklmnopqrstuvwxyz dev@example.com 4111111111111111 2001:db8::1"); len(matches) != 4 {
		t.Fatalf("prefilter changed detection results: %+v", matches)
	}
}

func TestContextualEntropyDetectorFindsUnknownTokens(t *testing.T) {
	value := "uW8xQ2mZ7pL4vN9cR5tK3sH6jD1fG0aB"
	matches := scan(t, NewDefault(), "client_secret: "+value)
	if len(matches) != 1 || matches[0].Value != value || matches[0].Finding.Detector != "entropy" || matches[0].Finding.Confidence != 0.8 {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestEntropyDetectorRequiresContextAndExcludesPlaceholders(t *testing.T) {
	value := "uW8xQ2mZ7pL4vN9cR5tK3sH6jD1fG0aB"
	if matches := scan(t, NewDefault(), "identifier "+value); len(matches) != 0 {
		t.Fatalf("context-free value matched: %+v", matches)
	}
	if matches := scan(t, NewDefault(), "token [[VEIL_TOKEN_4E13FA917EB2621A]]"); len(matches) != 0 {
		t.Fatalf("placeholder matched: %+v", matches)
	}
	if matches := scan(t, NewDefault(), "password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); len(matches) != 0 {
		t.Fatalf("low-entropy value matched: %+v", matches)
	}
}

func TestProviderSecretFamilies(t *testing.T) {
	text := "AKIAABCDEFGHIJKLMNOP xoxb-1234567890-abcdefghijklmnop glpat-abcdefghijklmnopqrst sk_live_abcdefghijklmnopqrst eyJabcdef.abcdefgh.abcdefgh"
	if matches := scan(t, NewDefault(), text); len(matches) != 5 {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestStructuredChineseValidators(t *testing.T) {
	scanner := NewDefault()
	valid := scan(t, scanner, "id 11010519491231002X uscc 91350211M000100Y46 tel 010-12345678")
	if len(valid) != 3 {
		t.Fatalf("valid=%+v", valid)
	}
	invalid := scan(t, scanner, "id 99010519490231002X uscc 91350211M000100Y44")
	if len(invalid) != 0 {
		t.Fatalf("invalid accepted=%+v", invalid)
	}
}

func TestInternationalStructuredPIIValidators(t *testing.T) {
	scanner := NewDefault()
	matches := scan(t, scanner, "ssn 123-45-6789 iban GB82WEST12345698765432 ipv6 2001:db8::1 loopback ::1")
	categories := make(map[string]int)
	for _, match := range matches {
		categories[match.Finding.Category]++
	}
	for category, want := range map[string]int{
		"pii.us.ssn": 1,
		"pii.iban":   1,
		"pii.ipv6":   2,
	} {
		if got := categories[category]; got != want {
			t.Fatalf("category %s count=%d want=%d matches=%+v", category, got, want, matches)
		}
	}
	if len(matches) != 4 {
		t.Fatalf("unexpected additional matches: %+v", matches)
	}

	invalid := scan(t, scanner, "000-12-3456 666-12-3456 900-12-3456 123-00-3456 123-45-0000 GB83WEST12345698765432")
	if len(invalid) != 0 {
		t.Fatalf("invalid structured identifiers accepted: %+v", invalid)
	}
}

func scan(t *testing.T, scanner *Scanner, text string) []Match {
	t.Helper()
	matches, err := scanner.ScanChecked("/x", text)
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func BenchmarkScannerOrdinaryText(b *testing.B) {
	scanner := NewDefault()
	text := strings.Repeat("ordinary prose without structured identifiers\n", 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := scanner.ScanChecked("/benchmark", text); err != nil {
			b.Fatal(err)
		}
	}
}
