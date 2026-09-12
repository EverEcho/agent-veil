package detector

import (
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/agentveil/agentveil/internal/domain"
)

type Match struct {
	Finding domain.Finding
	Value   string `json:"-"`
}
type rule struct {
	id, category string
	severity     domain.Severity
	action       domain.Action
	pattern      *regexp.Regexp
	validate     func(string) bool
}

type Scanner struct{ rules []rule }

func NewDefault() *Scanner {
	return &Scanner{rules: []rule{
		{"secret.private_key", "secret.private_key", domain.SeverityCritical, domain.ActionBlock, regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), nil},
		{"secret.github_pat", "secret.github_pat", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`), nil},
		{"secret.openai_key", "secret.openai_key", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), nil},
		{"pii.email", "pii.email", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b`), nil},
		{"pii.cn.phone", "pii.cn.phone", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b1[3-9][0-9]{9}\b`), nil},
		{"pii.cn.id_card", "pii.cn.id_card", domain.SeverityCritical, domain.ActionRedact, regexp.MustCompile(`\b[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]\b`), validCNID},
		{"pii.bank_card", "pii.bank_card", domain.SeverityHigh, domain.ActionRedact, regexp.MustCompile(`\b[0-9]{13,19}\b`), validLuhn},
	}}
}

func (s *Scanner) Scan(path, text string) []Match {
	var matches []Match
	for _, rule := range s.rules {
		for _, index := range rule.pattern.FindAllStringIndex(text, -1) {
			value := text[index[0]:index[1]]
			if rule.validate != nil && !rule.validate(value) {
				continue
			}
			matches = append(matches, Match{Finding: domain.Finding{RuleID: rule.id, Category: rule.category, Severity: rule.severity,
				Location: domain.ContentLocation{Path: path, Start: index[0], End: index[1]}, Confidence: 1, Detector: "deterministic", SuggestedAction: rule.action}, Value: value})
		}
	}
	return Merge(matches)
}

func Merge(matches []Match) []Match {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Finding.Location.Start != matches[j].Finding.Location.Start {
			return matches[i].Finding.Location.Start < matches[j].Finding.Location.Start
		}
		return priority(matches[i]) > priority(matches[j])
	})
	result := make([]Match, 0, len(matches))
	for _, candidate := range matches {
		if len(result) == 0 || candidate.Finding.Location.Start >= result[len(result)-1].Finding.Location.End {
			result = append(result, candidate)
			continue
		}
		if priority(candidate) > priority(result[len(result)-1]) {
			result[len(result)-1] = candidate
		}
	}
	return result
}

func priority(match Match) int {
	score := map[domain.Severity]int{domain.SeverityLow: 1, domain.SeverityMedium: 2, domain.SeverityHigh: 3, domain.SeverityCritical: 4}[match.Finding.Severity]
	if strings.HasPrefix(match.Finding.Category, "secret.") {
		score += 10
	}
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
