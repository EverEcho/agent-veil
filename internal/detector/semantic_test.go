package detector

import (
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

type fixedSemanticModel []map[string]float64

func (m fixedSemanticModel) Predict([]SemanticToken) ([]map[string]float64, error) { return m, nil }

func TestLocalSemanticDecodesBIESWithUTF8ByteOffsets(t *testing.T) {
	text := "联系张三。"
	scores := make([]map[string]float64, len([]rune(text)))
	labels := []string{"O", "O", "B-name", "E-name", "O"}
	for index, label := range labels {
		scores[index] = map[string]float64{"O": -4, "B-name": -4, "I-name": -4, "E-name": -4, "S-name": -4, label: 4}
	}
	detector, err := NewLocalSemantic(fixedSemanticModel(scores), map[string]SemanticEntity{"name": {Category: "pii.name", Severity: domain.SeverityHigh, Action: domain.ActionRedact}}, 32)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := detector.Detect("/input", text)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	finding := findings[0]
	if text[finding.Location.Start:finding.Location.End] != "张三" || finding.Detector != "semantic" || finding.Confidence < 0.99 {
		t.Fatalf("finding=%+v value=%q", finding, text[finding.Location.Start:finding.Location.End])
	}
}

func TestBIESDecoderRejectsInvalidOnlyPath(t *testing.T) {
	entities := map[string]SemanticEntity{"name": {Category: "pii.name", Severity: domain.SeverityHigh, Action: domain.ActionRedact}}
	if _, _, err := decodeBIES([]map[string]float64{{"I-name": 1}}, entities); err == nil {
		t.Fatal("invalid initial I label was accepted")
	}
}

func TestLocalSemanticRejectsInvalidUTF8AndTokenOverflow(t *testing.T) {
	model := fixedSemanticModel{{"O": 1}}
	detector, err := NewLocalSemantic(model, map[string]SemanticEntity{"name": {Category: "pii.name", Severity: domain.SeverityHigh, Action: domain.ActionRedact}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Detect("/input", string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
	if _, err := detector.Detect("/input", "ab"); err == nil {
		t.Fatal("semantic token overflow was accepted")
	}
}
