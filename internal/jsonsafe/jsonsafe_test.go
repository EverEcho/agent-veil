package jsonsafe

import (
	"strings"
	"testing"
)

func TestValidateAcceptsStrictJSON(t *testing.T) {
	if err := Validate([]byte(`{"object":{"text":"comma,} and // text"},"array":[1,true,null]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsAmbiguousAndInvalidJSON(t *testing.T) {
	deep := strings.Repeat("[", MaxNestingDepth+2) + strings.Repeat("]", MaxNestingDepth+2)
	for _, content := range [][]byte{
		[]byte(`{"route":"safe","route":"unsafe"}`),
		[]byte(`{"outer":{"token":1,"token":2}}`),
		[]byte(`{"value":NaN}`),
		[]byte(`{} {}`),
		[]byte(deep),
		{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	} {
		if err := Validate(content); err == nil {
			t.Fatalf("accepted invalid JSON: %q", content)
		}
	}
}
