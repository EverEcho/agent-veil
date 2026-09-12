package detector

import (
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/agentveil/agentveil/internal/domain"
)

type Match struct {
	Finding domain.Finding
	Value   string `json:"-"`
}

type ContentScanner interface {
	ScanChecked(path, text string) ([]Match, error)
}

type rule struct {
	id, category string
	severity     domain.Severity
	action       domain.Action
	pattern      *regexp.Regexp
	validate     func(string) bool
	group        int
}

type Semantic interface {
	Detect(path, text string) ([]domain.Finding, error)
}

var structuredRuleIDs = map[string]struct{}{
	"pii.cn.id_card": {},
	"pii.cn.uscc":    {},
	"pii.us.ssn":     {},
	"pii.iban":       {},
	"pii.bank_card":  {},
	"pii.ipv4":       {},
	"pii.ipv6":       {},
}

type Scanner struct {
	rules            []rule
	packRuleIDs      map[string]struct{}
	requiredFeatures map[string]featureSet
	requiredAny      map[string]featureSet
	prefixIndex      [256][]prefixCandidate
	prefixRules      map[string]struct{}
	semantic         Semantic
	semanticRequired bool
}

func NewDefault() *Scanner {
	scanner := &Scanner{rules: []rule{
		{"secret.private_key", "secret.private_key", domain.SeverityCritical, domain.ActionBlock, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`), nil, 0},
		{"secret.github_pat", "secret.github_pat", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`), nil, 0},
		{"secret.openai_key", "secret.openai_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b`), nil, 0},
		{"secret.anthropic_key", "secret.anthropic_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), nil, 0},
		{"secret.google_key", "secret.google_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{30,}\b`), nil, 0},
		{"secret.aws_access_key", "secret.aws_access_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), nil, 0},
		{"secret.slack_token", "secret.slack_token", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{16,}\b`), nil, 0},
		{"secret.gitlab_pat", "secret.gitlab_pat", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), nil, 0},
		{"secret.stripe_key", "secret.stripe_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b`), nil, 0},
		{"secret.jwt", "secret.jwt", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`), nil, 0},
		{"secret.bearer", "secret.bearer", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`(?i)\bBearer[ \t]+([A-Za-z0-9._~+/=-]{16,})`), highEntropy, 1},
		{"secret.database_url", "secret.database_url", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s]+`), nil, 0},
		{"secret.aws_secret_key", "secret.aws_secret_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`(?i)\bAWS_SECRET_ACCESS_KEY\s*=\s*["']?([A-Za-z0-9/+=]{40})["']?`), nil, 1},
		{"secret.assignment", "secret.assignment", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`(?i)(?:password|api_key|token)\s*=\s*["']?([^\s;"']{8,})["']?`), highEntropy, 1},
		{"pii.email", "pii.email", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b`), nil, 0},
		{"pii.cn.phone", "pii.cn.phone", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b1[3-9][0-9]{9}\b`), nil, 0},
		{"pii.cn.landline", "pii.cn.landline", domain.SeverityMedium, domain.ActionRedact, regexp.MustCompile(`\b0[1-9][0-9]{1,2}-?[0-9]{7,8}\b`), nil, 0},
		{"pii.cn.id_card", "pii.cn.id_card", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]\b`), validCNID, 0},
		{"pii.cn.uscc", "pii.cn.uscc", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b[0-9ABCDEFGHJKLMNPQRTUWXY]{18}\b`), validUSCC, 0},
		{"pii.us.ssn", "pii.us.ssn", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`), validUSSSN, 0},
		{"pii.iban", "pii.iban", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`), validIBAN, 0},
		{"pii.bank_card", "pii.bank_card", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b[0-9]{13,19}\b`), validLuhn, 0},
		{"pii.ipv4", "pii.ipv4", domain.SeverityMedium, domain.ActionRedact, regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`), validIP, 0},
		{"pii.ipv6", "pii.ipv6", domain.SeverityMedium, domain.ActionRedact, regexp.MustCompile(`[0-9A-Fa-f:]{2,39}`), validIPv6, 0},
		{"pii.mac", "pii.mac", domain.SeverityMedium, domain.ActionRedact, regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`), nil, 0},
	}}
	scanner.requiredFeatures = map[string]featureSet{
		"secret.private_key":    featureDash,
		"secret.github_pat":     featureUnderscore,
		"secret.openai_key":     featureDash,
		"secret.anthropic_key":  featureDash,
		"secret.slack_token":    featureDash,
		"secret.gitlab_pat":     featureDash,
		"secret.stripe_key":     featureUnderscore,
		"secret.jwt":            featureDot,
		"secret.database_url":   featureColon | featureSlash,
		"secret.aws_secret_key": featureUnderscore | featureEqual,
		"secret.assignment":     featureEqual,
		"pii.email":             featureAt | featureDot,
		"pii.cn.phone":          featureDigit,
		"pii.cn.landline":       featureDigit,
		"pii.cn.id_card":        featureDigit,
		"pii.us.ssn":            featureDash | featureDigit,
		"pii.iban":              featureDigit,
		"pii.bank_card":         featureDigit,
		"pii.ipv4":              featureDigit | featureDot,
		"pii.ipv6":              featureColon,
		"pii.mac":               featureColon,
	}
	scanner.requiredAny = map[string]featureSet{
		"pii.cn.uscc": featureDigit | featureUpper,
	}
	prefixes := map[string][]string{
		"secret.private_key":    {"-----BEGIN "},
		"secret.github_pat":     {"ghp_", "github_pat_"},
		"secret.openai_key":     {"sk-"},
		"secret.anthropic_key":  {"sk-ant-"},
		"secret.google_key":     {"AIza"},
		"secret.aws_access_key": {"AKIA", "ASIA"},
		"secret.slack_token":    {"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
		"secret.gitlab_pat":     {"glpat-"},
		"secret.stripe_key":     {"sk_live_", "rk_live_"},
		"secret.jwt":            {"eyJ"},
		"secret.database_url":   {"postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://"},
	}
	foldedPrefixes := map[string][]string{
		"secret.bearer": {"bearer"},
	}
	scanner.prefixIndex, scanner.prefixRules = buildPrefixIndex(prefixes, foldedPrefixes)
	return scanner
}

type prefixCandidate struct {
	ruleID   string
	value    string
	foldCase bool
}

type featureSet uint16

const (
	featureDigit featureSet = 1 << iota
	featureAt
	featureUnderscore
	featureDash
	featureDot
	featureSlash
	featureEqual
	featureColon
	featureUpper
)

func (s *Scanner) WithSemantic(semantic Semantic, required bool) *Scanner {
	s.semantic = semantic
	s.semanticRequired = required
	return s
}

func (s *Scanner) ScanChecked(path, text string) (matches []Match, err error) {
	defer func() {
		if recover() != nil {
			matches = nil
			err = domain.NewError(domain.ErrDetectorFailure, "scan content", "detector panicked")
		}
	}()
	features := scanFeatures(text)
	prefixCandidates := s.scanPrefixCandidates(text)
	for _, rule := range s.rules {
		if !s.isCandidate(rule, features, prefixCandidates) {
			continue
		}
		for _, indices := range rule.pattern.FindAllStringSubmatchIndex(text, -1) {
			index := indices[:2]
			if rule.group > 0 && rule.group*2+1 < len(indices) {
				index = indices[rule.group*2 : rule.group*2+2]
			}
			if index[0] < 0 || index[1] <= index[0] {
				continue
			}
			value := text[index[0]:index[1]]
			if rule.validate != nil && !rule.validate(value) {
				continue
			}
			detectorName := "deterministic"
			if _, packed := s.packRuleIDs[rule.id]; packed {
				detectorName = "rule_pack"
			}
			if _, structured := structuredRuleIDs[rule.id]; structured {
				detectorName = "structured"
			}
			matches = append(matches, Match{Finding: domain.Finding{RuleID: rule.id, Category: rule.category, Severity: rule.severity,
				Location: domain.ContentLocation{Path: path, Start: index[0], End: index[1]}, Confidence: 1, Detector: detectorName, SuggestedAction: rule.action}, Value: value})
		}
	}
	matches = append(matches, scanEntropyCandidates(path, text)...)
	if s.semantic == nil {
		if s.semanticRequired {
			return nil, domain.NewError(domain.ErrDetectorFailure, "semantic detection", "required local semantic detector is unavailable")
		}
		return Merge(matches), nil
	}
	findings, err := s.semantic.Detect(path, text)
	if err != nil {
		if s.semanticRequired {
			return nil, domain.NewError(domain.ErrDetectorFailure, "semantic detection", "required local semantic detector failed")
		}
		return Merge(matches), nil
	}
	for _, finding := range findings {
		if err := finding.Validate(len(text)); err != nil || finding.Location.Path != path {
			return nil, domain.NewError(domain.ErrDetectorFailure, "semantic detection", "semantic detector returned an invalid finding")
		}
		matches = append(matches, Match{Finding: finding, Value: text[finding.Location.Start:finding.Location.End]})
	}
	return Merge(matches), nil
}

func (s *Scanner) isCandidate(candidate rule, features featureSet, prefixCandidates map[string]struct{}) bool {
	required := s.requiredFeatures[candidate.id]
	if features&required != required {
		return false
	}
	if required := s.requiredAny[candidate.id]; required != 0 && features&required == 0 {
		return false
	}
	if _, indexed := prefixCandidates[candidate.id]; indexed {
		return true
	}
	_, indexed := s.prefixRules[candidate.id]
	return !indexed
}

func buildPrefixIndex(prefixes, foldedPrefixes map[string][]string) ([256][]prefixCandidate, map[string]struct{}) {
	var index [256][]prefixCandidate
	rules := make(map[string]struct{}, len(prefixes)+len(foldedPrefixes))
	for ruleID, values := range prefixes {
		for _, value := range values {
			if value == "" {
				continue
			}
			index[value[0]] = append(index[value[0]], prefixCandidate{ruleID: ruleID, value: value})
			rules[ruleID] = struct{}{}
		}
	}
	for ruleID, values := range foldedPrefixes {
		for _, value := range values {
			if value == "" {
				continue
			}
			candidate := prefixCandidate{ruleID: ruleID, value: value, foldCase: true}
			index[value[0]] = append(index[value[0]], candidate)
			if value[0] >= 'a' && value[0] <= 'z' {
				index[value[0]-'a'+'A'] = append(index[value[0]-'a'+'A'], candidate)
			}
			rules[ruleID] = struct{}{}
		}
	}
	return index, rules
}

func (s *Scanner) scanPrefixCandidates(text string) map[string]struct{} {
	matches := make(map[string]struct{})
	for offset := 0; offset < len(text); offset++ {
		for _, candidate := range s.prefixIndex[text[offset]] {
			if _, matched := matches[candidate.ruleID]; matched {
				continue
			}
			if len(text)-offset < len(candidate.value) {
				continue
			}
			value := text[offset : offset+len(candidate.value)]
			if value == candidate.value || candidate.foldCase && strings.EqualFold(value, candidate.value) {
				matches[candidate.ruleID] = struct{}{}
			}
		}
	}
	return matches
}

func scanFeatures(text string) featureSet {
	var result featureSet
	for index := 0; index < len(text); index++ {
		switch character := text[index]; {
		case character >= '0' && character <= '9':
			result |= featureDigit
		case character == '@':
			result |= featureAt
		case character == '_':
			result |= featureUnderscore
		case character == '-':
			result |= featureDash
		case character == '.':
			result |= featureDot
		case character == '/':
			result |= featureSlash
		case character == '=':
			result |= featureEqual
		case character == ':':
			result |= featureColon
		case character >= 'A' && character <= 'Z':
			result |= featureUpper
		}
	}
	return result
}

func Merge(matches []Match) []Match {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Finding.Location.Path != matches[j].Finding.Location.Path {
			return matches[i].Finding.Location.Path < matches[j].Finding.Location.Path
		}
		if matches[i].Finding.Location.Start != matches[j].Finding.Location.Start {
			return matches[i].Finding.Location.Start < matches[j].Finding.Location.Start
		}
		return priority(matches[i]) > priority(matches[j])
	})
	result := make([]Match, 0, len(matches))
	for _, candidate := range matches {
		if len(result) == 0 || candidate.Finding.Location.Path != result[len(result)-1].Finding.Location.Path || candidate.Finding.Location.Start >= result[len(result)-1].Finding.Location.End {
			result = append(result, candidate)
			continue
		}
		current := result[len(result)-1]
		unionEnd := current.Finding.Location.End
		unionValue := current.Value
		if candidate.Finding.Location.End > unionEnd {
			unionValue += candidate.Value[unionEnd-candidate.Finding.Location.Start:]
			unionEnd = candidate.Finding.Location.End
		}
		if priority(candidate) > priority(current) {
			current = candidate
		}
		current.Finding.Location.Start = result[len(result)-1].Finding.Location.Start
		current.Finding.Location.End = unionEnd
		current.Finding.Location.Path = result[len(result)-1].Finding.Location.Path
		current.Value = unionValue
		result[len(result)-1] = current
	}
	return result
}

func priority(match Match) int {
	score := map[domain.Severity]int{domain.SeverityLow: 10, domain.SeverityMedium: 20, domain.SeverityHigh: 30, domain.SeverityCritical: 40}[match.Finding.Severity]
	if match.Finding.Detector == "structured" {
		score += 1000
	}
	if strings.HasPrefix(match.Finding.Category, "secret.") && match.Finding.Detector != "entropy" {
		score += 500
	}
	score += strings.Count(match.Finding.RuleID, ".")
	return score
}

func validLuhn(value string) bool {
	sum, parity := 0, len(value)%2
	for i, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
		digit := int(r - '0')
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}
func validCNID(value string) bool {
	if len(value) != 18 {
		return false
	}
	provinces := map[string]struct{}{"11": {}, "12": {}, "13": {}, "14": {}, "15": {}, "21": {}, "22": {}, "23": {}, "31": {}, "32": {}, "33": {}, "34": {}, "35": {}, "36": {}, "37": {}, "41": {}, "42": {}, "43": {}, "44": {}, "45": {}, "46": {}, "50": {}, "51": {}, "52": {}, "53": {}, "54": {}, "61": {}, "62": {}, "63": {}, "64": {}, "65": {}, "71": {}, "81": {}, "82": {}}
	if _, ok := provinces[value[:2]]; !ok {
		return false
	}
	if _, err := time.Parse("20060102", value[6:14]); err != nil {
		return false
	}
	weights := [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	sum := 0
	for i := 0; i < 17; i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		sum += int(value[i]-'0') * weights[i]
	}
	return byte(unicode.ToUpper(rune(value[17]))) == checks[sum%11]
}

func validUSCC(value string) bool {
	const alphabet = "0123456789ABCDEFGHJKLMNPQRTUWXY"
	weights := [17]int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}
	sum := 0
	for i := 0; i < 17; i++ {
		index := strings.IndexByte(alphabet, value[i])
		if index < 0 {
			return false
		}
		sum += index * weights[i]
	}
	expected := alphabet[(31-sum%31)%31]
	return value[17] == expected
}

func validUSSSN(value string) bool {
	if len(value) != 11 || value[3] != '-' || value[6] != '-' {
		return false
	}
	area := int(value[0]-'0')*100 + int(value[1]-'0')*10 + int(value[2]-'0')
	return area != 0 && area != 666 && area < 900 && value[4:6] != "00" && value[7:] != "0000"
}

func validIBAN(value string) bool {
	if len(value) < 15 || len(value) > 34 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' || value[2] < '0' || value[2] > '9' || value[3] < '0' || value[3] > '9' {
		return false
	}
	reordered := value[4:] + value[:4]
	remainder := 0
	for _, character := range reordered {
		switch {
		case character >= '0' && character <= '9':
			remainder = (remainder*10 + int(character-'0')) % 97
		case character >= 'A' && character <= 'Z':
			remainder = (remainder*100 + int(character-'A') + 10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func validIP(value string) bool { return net.ParseIP(value) != nil }
func validIPv6(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() == nil
}

func highEntropy(value string) bool {
	if len(value) < 12 {
		return false
	}
	counts := map[rune]float64{}
	runes := []rune(value)
	for _, r := range runes {
		counts[r]++
	}
	entropy, total := 0.0, float64(len(runes))
	for _, count := range counts {
		probability := count / total
		entropy -= probability * math.Log2(probability)
	}
	return entropy >= 3.0
}
