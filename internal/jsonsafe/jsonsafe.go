package jsonsafe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	MaxNestingDepth = 64
	MaxJSONTokens   = 256 << 10
)

// Validate accepts exactly one strict JSON value and rejects duplicate object
// keys. This prevents review/runtime ambiguity caused by last-key-wins decoders.
func Validate(content []byte) error {
	if !utf8.Valid(content) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	tokens := 0
	if err := validateValue(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func validateValue(decoder *json.Decoder, depth int, tokens *int) error {
	if depth > MaxNestingDepth {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := nextToken(decoder, tokens)
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
			keyToken, err := nextToken(decoder, tokens)
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
			if err := validateValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		closing, err := nextToken(decoder, tokens)
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := validateValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		closing, err := nextToken(decoder, tokens)
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func nextToken(decoder *json.Decoder, tokens *int) (json.Token, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	(*tokens)++
	if *tokens > MaxJSONTokens {
		return nil, errors.New("JSON token limit exceeded")
	}
	return token, nil
}
