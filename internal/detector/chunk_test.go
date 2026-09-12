package detector

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

type failedSemantic struct{}

func (failedSemantic) Detect(string, string) ([]domain.Finding, error) {
	return nil, errors.New("model unavailable")
}

type panickingSemantic struct{}

func (panickingSemantic) Detect(string, string) ([]domain.Finding, error) {
	panic("model runtime fault")
}

func TestRequiredSemanticDetectorFailsClosed(t *testing.T) {
	_, err := NewDefault().WithSemantic(failedSemantic{}, true).ScanChecked("/x", "ordinary text")
	var veil *domain.VeilError
	if !errors.As(err, &veil) || veil.Code != domain.ErrDetectorFailure {
		t.Fatalf("error=%v", err)
	}
}

func TestDetectorPanicIsRecoveredAndFailsClosed(t *testing.T) {
	_, err := NewDefault().WithSemantic(panickingSemantic{}, false).ScanChecked("/x", "ordinary text")
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

func TestChunkCacheEvictsOldestEntryAtLimit(t *testing.T) {
	scanner, err := NewChunkedWithCacheLimit(NewDefault(), 256, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))
	third := sha256.Sum256([]byte("third"))
	scanner.store(first, []domain.Finding{{RuleID: "first"}})
	scanner.store(second, []domain.Finding{{RuleID: "second"}})
	scanner.store(third, []domain.Finding{{RuleID: "third"}})

	if len(scanner.cache) != 2 || len(scanner.cacheOrder) != 2 {
		t.Fatalf("cache grew beyond limit: entries=%d order=%d", len(scanner.cache), len(scanner.cacheOrder))
	}
	if _, ok := scanner.cached(first); ok {
		t.Fatal("oldest cache entry was not evicted")
	}
	if _, ok := scanner.cached(second); !ok {
		t.Fatal("second cache entry was unexpectedly evicted")
	}
	if _, ok := scanner.cached(third); !ok {
		t.Fatal("newest cache entry was unexpectedly evicted")
	}
}

func TestChunkCacheRejectsInvalidLimit(t *testing.T) {
	if _, err := NewChunkedWithCacheLimit(NewDefault(), 256, 64, 0); err == nil {
		t.Fatal("expected zero cache limit to be rejected")
	}
}
