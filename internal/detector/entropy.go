package detector

import (
	"regexp"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const entropyContextBytes = 48

var (
	entropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9_~+./=-]{20,}`)
	entropyContextPattern   = regexp.MustCompile(`(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|secret|token|password|credential|authorization|auth)`)
)

func scanEntropyCandidates(path, text string) []Match {
	if !entropyContextPattern.MatchString(text) {
		return nil
	}
	var matches []Match
	for _, location := range entropyCandidatePattern.FindAllStringIndex(text, -1) {
		value := text[location[0]:location[1]]
		if strings.HasPrefix(value, "VEIL_") || entropyContextPattern.MatchString(value) || !hasCharacterDiversity(value) || !highEntropy(value) {
			continue
		}
		contextStart := location[0] - entropyContextBytes
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := location[1] + entropyContextBytes
		if contextEnd > len(text) {
			contextEnd = len(text)
		}
		context := text[contextStart:location[0]] + text[location[1]:contextEnd]
		if !entropyContextPattern.MatchString(context) {
			continue
		}
		matches = append(matches, Match{
			Finding: domain.Finding{
				RuleID:          "secret.high_entropy",
				Category:        "secret.high_entropy",
				Severity:        domain.SeverityHigh,
				Location:        domain.ContentLocation{Path: path, Start: location[0], End: location[1]},
				Confidence:      0.8,
				Detector:        "entropy",
				SuggestedAction: domain.ActionRedact,
			},
			Value: value,
		})
	}
	return matches
}

func hasCharacterDiversity(value string) bool {
	var classes uint8
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
			classes |= 1
		case character >= 'A' && character <= 'Z':
			classes |= 2
		case character >= '0' && character <= '9':
			classes |= 4
		default:
			classes |= 8
		}
	}
	return classes != 0 && classes&(classes-1) != 0
}
