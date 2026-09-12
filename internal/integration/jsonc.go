package integration

import (
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const maxJSONNestingDepth = jsonsafe.MaxNestingDepth

// validateJSONC removes comments and trailing commas, then validates strict
// JSON tokens and rejects duplicate object keys before typed decoding.
func validateJSONC(content []byte) ([]byte, error) {
	cleaned, err := stripJSON5Comments(content)
	if err != nil {
		return nil, err
	}
	cleaned = stripJSONTrailingCommas(cleaned)
	if err := jsonsafe.Validate(cleaned); err != nil {
		return nil, err
	}
	return cleaned, nil
}

func stripJSONTrailingCommas(content []byte) []byte {
	cleaned := append([]byte(nil), content...)
	inString, escaped := false, false
	for index := 0; index < len(cleaned); index++ {
		character := cleaned[index]
		if inString {
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == '"' {
				inString = false
			}
			continue
		}
		if character == '"' {
			inString = true
			continue
		}
		if character != ',' {
			continue
		}
		next := index + 1
		for next < len(cleaned) && (cleaned[next] == ' ' || cleaned[next] == '\t' || cleaned[next] == '\r' || cleaned[next] == '\n') {
			next++
		}
		if next < len(cleaned) && (cleaned[next] == '}' || cleaned[next] == ']') {
			cleaned[index] = ' '
		}
	}
	return cleaned
}
