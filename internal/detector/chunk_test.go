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

type pathSemantic struct{}

func (pathSemantic) Detect(path, text string) ([]domain.Finding, error) {
	if path != "/sensitive" || text == "" {
		return nil, nil
	}
	return []domain.Finding{{RuleID: "pii.semantic_name", Category: "pii.semantic_name", Severity: domain.SeverityHigh, Location: domain.ContentLocation{Path: path, Start: 0, End: 1}, Confidence: 0.8, Detector: "semantic", SuggestedAction: domain.ActionRedact}}, nil
}

type countingSemantic struct{ calls int }

func (s *countingSemantic) Detect(string, string) ([]domain.Finding, error) {
	s.calls++
	return nil, nil
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

func TestStableChunkEndPrefersNewlineThenWhitespace(t *testing.T) {
	text := strings.Repeat("a", 210) + "\n" + strings.Repeat("b", 20) + " " + strings.Repeat("c", 100)
	if end := stableChunkEnd(text, 0, 256, 64); end != 211 {
		t.Fatalf("newline end=%d", end)
	}

	text = strings.Repeat("a", 220) + "\u3000" + strings.Repeat("b", 100)
	want := 220 + len("\u3000")
	if end := stableChunkEnd(text, 0, 256, 64); end != want {
		t.Fatalf("unicode whitespace end=%d want=%d", end, want)
	}
}

func TestStableChunkEndFallsBackToUTF8Boundary(t *testing.T) {
	text := strings.Repeat("a", 255) + "界" + strings.Repeat("b", 100)
	if end := stableChunkEnd(text, 0, 256, 64); end != 255 {
		t.Fatalf("hard end split a UTF-8 rune: %d", end)
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

func TestChunkCacheKeyIncludesSemanticFieldPath(t *testing.T) {
	scanner, err := NewChunked(NewDefault().WithSemantic(pathSemantic{}, true), 256, 64)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("a", 128)
	if matches, err := scanner.ScanChecked("/sensitive", text); err != nil || len(matches) != 1 {
		t.Fatalf("sensitive scan matches=%+v err=%v", matches, err)
	}
	if matches, err := scanner.ScanChecked("/ordinary", text); err != nil || len(matches) != 0 {
		t.Fatalf("path-dependent finding was reused: matches=%+v err=%v", matches, err)
	}
}

func TestChunkCacheReusesRepeatedConversationContent(t *testing.T) {
	semantic := &countingSemantic{}
	scanner, err := NewChunked(NewDefault().WithSemantic(semantic, true), 256, 64)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("ordinary conversation history ", 4)
	for range 2 {
		if _, err := scanner.ScanChecked("/input", text); err != nil {
			t.Fatal(err)
		}
	}
	if semantic.calls != 1 {
		t.Fatalf("semantic detector calls=%d want=1", semantic.calls)
	}
}
