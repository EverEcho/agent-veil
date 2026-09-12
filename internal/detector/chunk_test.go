package detector

import (
	"errors"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

type failedSemantic struct{}

func (failedSemantic) Detect(string, string) ([]domain.Finding, error) {
	return nil, errors.New("model unavailable")
}

func TestRequiredSemanticDetectorFailsClosed(t *testing.T) {
	_, err := NewDefault().WithSemantic(failedSemantic{}, true).ScanChecked("/x", "ordinary text")
	var veil *domain.VeilError
	if !errors.As(err, &veil) || veil.Code != domain.ErrDetectorFailure {
		t.Fatalf("error=%v", err)
	}
}

func TestChunkOverlapFindsBoundaryEntity(t *testing.T) {
	scanner, _ := NewChunked(NewDefault(), 256, 64)
	text := strings.Repeat("a", 245) + " dev@example.com " + strings.Repeat("b", 300)
	matches, err := scanner.Scan("/input", text)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Value != "dev@example.com" {
		t.Fatalf("matches=%+v", matches)
	}
	for _, findings := range scanner.cache {
		for _, finding := range findings {
			if finding.Location.Path != "" {
				t.Fatal("cache retained request path")
			}
		}
	}
}
