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

type panickingContentScanner struct{}

func (*panickingContentScanner) ScanChecked(string, string) ([]Match, error) {
	panic("replaceable scanner fault")
}

func TestScanContentFailsClosedForUnavailableOrPanickingScanner(t *testing.T) {
	for _, scanner := range []ContentScanner{nil, (*panickingContentScanner)(nil)} {
		matches, err := ScanContent(scanner, "/input", "must not escape")
		var veil *domain.VeilError
		if matches != nil || !errors.As(err, &veil) || veil.Code != domain.ErrDetectorFailure {
			t.Fatalf("matches=%+v error=%v", matches, err)
		}
	}
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

func TestMarkdownEscapedEmailIsDetectedAsOneValue(t *testing.T) {
	value := `privacy-test\@example.invalid`
	matches := scan(t, NewDefault(), "这个是我邮箱 "+value+"，请逐字返回")
	if len(matches) != 1 || matches[0].Finding.Category != "pii.email" || matches[0].Value != value {
		t.Fatalf("escaped email matches=%+v", matches)
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

func TestMergeFollowsValidatedSecretAndSpecificityPriority(t *testing.T) {
	location := domain.ContentLocation{Path: "/x", Start: 0, End: 10}
	tests := []struct {
		name    string
		matches []Match
		winner  string
	}{
		{"validated-result", []Match{
			{Finding: domain.Finding{RuleID: "secret.token", Category: "secret.token", Severity: domain.SeverityCritical, Detector: "deterministic", Location: location}, Value: "0123456789"},
			{Finding: domain.Finding{RuleID: "pii.bank_card", Category: "pii.bank_card", Severity: domain.SeverityHigh, Detector: "structured", Location: location}, Value: "0123456789"},
		}, "pii.bank_card"},
		{"known-secret-over-entropy", []Match{
			{Finding: domain.Finding{RuleID: "secret.high_entropy", Category: "secret.high_entropy", Severity: domain.SeverityCritical, Detector: "entropy", Location: location}, Value: "0123456789"},
			{Finding: domain.Finding{RuleID: "secret.github_pat", Category: "secret.github_pat", Severity: domain.SeverityHigh, Detector: "deterministic", Location: location}, Value: "0123456789"},
		}, "secret.github_pat"},
		{"specific-rule", []Match{
			{Finding: domain.Finding{RuleID: "pii.address", Category: "pii.address", Severity: domain.SeverityHigh, Detector: "semantic", Location: location}, Value: "0123456789"},
			{Finding: domain.Finding{RuleID: "pii.address.street", Category: "pii.address.street", Severity: domain.SeverityHigh, Detector: "semantic", Location: location}, Value: "0123456789"},
		}, "pii.address.street"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			merged := Merge(test.matches)
			if len(merged) != 1 || merged[0].Finding.RuleID != test.winner {
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

func TestSensitiveEnvironmentAssignmentsIncludingMarkdownEscapes(t *testing.T) {
	values := []string{
		"0f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"f1e2d3c4b5a69788796a5b4c3d2e1f00",
		"SyntheticCloudSecret9x7v5t3r1p",
		"tk-synthetic-provider-key-9876543210",
	}
	text := strings.Join([]string{
		"USER\\_AES\\_IV=" + values[0],
		"USER\\_AES\\_KEY=" + values[1],
		"ALIYUN\\_OSS\\_ACCESS\\_KEY\\_SECRET=" + values[2],
		"OPENAI\\_API\\_KEY=" + values[3],
	}, "\n")
	matches := scan(t, NewDefault(), text)
	if len(matches) != len(values) {
		t.Fatalf("environment matches=%+v", matches)
	}
	for index, match := range matches {
		if match.Finding.Category != "secret.assignment" || match.Value != values[index] {
			t.Fatalf("environment match[%d]=%+v", index, match)
		}
	}
}

func TestSensitiveEnvironmentAssignmentsAvoidOrdinaryConfiguration(t *testing.T) {
	text := strings.Join([]string{
		"ENV=dev",
		"BASE_URL=https://service.example.invalid/v1",
		"BUCKET_NAME=sample-assets",
		"CACHE_KEY=user-profile",
		"PRIMARY_KEY=id",
		"ENABLE_QUEUE=true",
	}, "\n")
	if matches := scan(t, NewDefault(), text); len(matches) != 0 {
		t.Fatalf("ordinary configuration was treated as secret: %+v", matches)
	}
}

func TestSensitiveEnvironmentAssignmentsDoNotDependOnEntropy(t *testing.T) {
	matches := scan(t, NewDefault(), "DB_PASSWORD=abc123\nSERVICE_TOKEN=short-key")
	if len(matches) != 2 || matches[0].Value != "abc123" || matches[1].Value != "short-key" {
		t.Fatalf("low-entropy assigned secrets were missed: %+v", matches)
	}
	if matches := scan(t, NewDefault(), "SERVICE_TOKEN=${SERVICE_TOKEN}\nDIRECT_TOKEN=$DIRECT_TOKEN\nCOMMAND_SECRET=$(secret-tool lookup service sample)\nOPTIONAL_SECRET=<占位符>\nAUTH=false\nPASSWORD=[REDACTED]"); len(matches) != 0 {
		t.Fatalf("secret references or sentinel values were redacted: %+v", matches)
	}
	if matches := scan(t, NewDefault(), "PASSWORD=$2b$12$syntheticbcryptvalue"); len(matches) != 1 || matches[0].Value != "$2b$12$syntheticbcryptvalue" {
		t.Fatalf("literal dollar-prefixed secret was skipped: %+v", matches)
	}
}

func TestEntropyContextDoesNotCrossEnvironmentLines(t *testing.T) {
	text := "SERVICE_SECRET=SyntheticSecretValue987654321\nBASE_URL=https://service.example.invalid/a/long/path"
	matches := scan(t, NewDefault(), text)
	if len(matches) != 1 || matches[0].Finding.Category != "secret.assignment" || matches[0].Value != "SyntheticSecretValue987654321" {
		t.Fatalf("entropy context crossed an environment line: %+v", matches)
	}
}

func TestDatabaseURLWithDriverSuffixIsDetected(t *testing.T) {
	value := "mysql+pymysql://sample_user:synthetic-pass-9876@db.example.invalid/app"
	matches := scan(t, NewDefault(), value)
	if len(matches) != 1 || matches[0].Finding.Category != "secret.database_url" || matches[0].Value != value {
		t.Fatalf("driver URL matches=%+v", matches)
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

func TestModelProviderTokenFamilies(t *testing.T) {
	text := "huggingface=hf_abcdefghijklmnopqrstuvwxyz12345678 oauth=hf_oauth_abcdefghijklmnopqrstuvwxyz12345678 groq=gsk_abcdefghijklmnopqrstuvwxyz12345678"
	matches := scan(t, NewDefault(), text)
	counts := make(map[string]int)
	for _, match := range matches {
		counts[match.Finding.Category]++
		if match.Finding.Detector != "deterministic" || match.Finding.SuggestedAction != domain.ActionRedact {
			t.Fatalf("unexpected model provider finding: %+v", match)
		}
	}
	if counts["secret.huggingface_token"] != 2 || counts["secret.groq_key"] != 1 || len(matches) != 3 {
		t.Fatalf("matches=%+v", matches)
	}
	if matches := scan(t, NewDefault(), "docs hf_... hf_short gsk_example"); len(matches) != 0 {
		t.Fatalf("short model provider lookalikes matched: %+v", matches)
	}
}

func TestDomesticCloudAccessKeyFamilies(t *testing.T) {
	values := map[string]string{
		"secret.alibaba_access_key":    "LTAI5tExampleKey123456",
		"secret.tencent_secret_id":     "AKIDabcdefghijklmnopqrstuvwxyz123456",
		"secret.volcengine_access_key": "AKLTYWViMTVmZGYzM2E0NDI5Mzk2MDZjNjFmMjc2MjRjMzg",
	}
	text := "aliyun=" + values["secret.alibaba_access_key"] + " tencent=" + values["secret.tencent_secret_id"] + " volcengine=" + values["secret.volcengine_access_key"]
	matches := scan(t, NewDefault(), text)
	if len(matches) != len(values) {
		t.Fatalf("matches=%+v", matches)
	}
	for _, match := range matches {
		if want := values[match.Finding.Category]; want == "" || match.Value != want || match.Finding.SuggestedAction != domain.ActionRedact {
			t.Fatalf("unexpected domestic cloud finding: %+v", match)
		}
	}
	if matches := scan(t, NewDefault(), "ordinary LTAIshort AKIDexample AKLTsample identifiers"); len(matches) != 0 {
		t.Fatalf("short lookalikes matched: %+v", matches)
	}
}

func TestStructuredChineseValidators(t *testing.T) {
	scanner := NewDefault()
	valid := scan(t, scanner, "id 11010519491231002X uscc 91350211M000100Y46 tel 010-12345678")
	if len(valid) != 3 {
		t.Fatalf("valid=%+v", valid)
	}
	for _, match := range valid {
		if match.Finding.Category != "pii.cn.landline" && match.Finding.Detector != "structured" {
			t.Fatalf("validated match source=%q", match.Finding.Detector)
		}
	}
	invalid := scan(t, scanner, "id 99010519490231002X uscc 91350211M000100Y44")
	if len(invalid) != 0 {
		t.Fatalf("invalid accepted=%+v", invalid)
	}
}

func TestChineseCivilianLicensePlateValidator(t *testing.T) {
	matches := scan(t, NewDefault(), "ordinary 京A12345 separated 冀B·6C789 small-new-energy 沪AD12345 large-new-energy 粤B12345F")
	if len(matches) != 4 {
		t.Fatalf("valid civilian plates were not detected: %+v", matches)
	}
	for _, match := range matches {
		if match.Finding.Category != "pii.cn.license_plate" || match.Finding.Detector != "structured" {
			t.Fatalf("plate was not structurally attributed: %+v", match)
		}
	}
	invalid := scan(t, NewDefault(), "京I12345 京AO12345 沪AG12345 粤B1234AF 京A1234567")
	if len(invalid) != 0 {
		t.Fatalf("invalid civilian plates accepted: %+v", invalid)
	}
}

func TestChineseOrdinaryPassportFormats(t *testing.T) {
	matches := scan(t, NewDefault(), "old G12345678 electronic E12345678 current EA1234567")
	if len(matches) != 3 {
		t.Fatalf("valid ordinary passports were not detected: %+v", matches)
	}
	for _, match := range matches {
		if match.Finding.Category != "pii.cn.passport" || match.Finding.Detector != "structured" || match.Finding.SuggestedAction != domain.ActionRedact {
			t.Fatalf("passport was not structurally attributed: %+v", match)
		}
	}
	invalid := scan(t, NewDefault(), "E1234567 E123456789 EI1234567 EO1234567 g12345678")
	if len(invalid) != 0 {
		t.Fatalf("invalid ordinary passports accepted: %+v", invalid)
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
