package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const maxJSONNestingDepth = 64

// validateJSONC removes comments and trailing commas, then validates strict
// JSON tokens and rejects duplicate object keys before typed decoding.
func validateJSONC(content []byte) ([]byte, error) {
	if !utf8.Valid(content) {
		return nil, errors.New("JSONC is not valid UTF-8")
	}
	cleaned, err := stripJSON5Comments(content)
	if err != nil {
		return nil, err
	}
	cleaned = stripJSONTrailingCommas(cleaned)
	decoder := json.NewDecoder(bytes.NewReader(cleaned))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON contains trailing data")
	}
	return cleaned, nil
}

func validateJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONNestingDepth {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
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
