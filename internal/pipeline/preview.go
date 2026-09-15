package pipeline

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/detector"
)

const maxAuditPreviewRunes = 180

type previewRange struct {
	start int
	end   int
}

// buildAuditPreview returns a short, single-line fragment around a finding.
// Every finding in the field is replaced before the fragment is selected, so
// the audit log never needs the original matched values.
func buildAuditPreview(text string, matches []detector.Match) string {
	ranges := make([]previewRange, 0, len(matches))
	for _, match := range matches {
		start, end := match.Finding.Location.Start, match.Finding.Location.End
		if start >= 0 && end > start && end <= len(text) {
			ranges = append(ranges, previewRange{start: start, end: end})
		}
	}
	if len(ranges) == 0 {
		return ""
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || current.start > merged[len(merged)-1].end {
			merged = append(merged, current)
			continue
		}
		if current.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = current.end
		}
	}
	var sanitized strings.Builder
	last := 0
	for _, current := range merged {
		sanitized.WriteString(text[last:current.start])
		sanitized.WriteString("***")
		last = current.end
	}
	sanitized.WriteString(text[last:])
	normalized := strings.Join(strings.Fields(sanitized.String()), " ")
	if normalized == "" {
		return "***"
	}
	runes := []rune(normalized)
	if len(runes) <= maxAuditPreviewRunes {
		return normalized
	}
	anchorBytes := strings.LastIndex(normalized, "***")
	anchor := 0
	if anchorBytes >= 0 {
		anchor = utf8.RuneCountInString(normalized[:anchorBytes])
	}
	start := anchor - maxAuditPreviewRunes/3
	if start < 0 {
		start = 0
	}
	end := start + maxAuditPreviewRunes
	if end > len(runes) {
		end = len(runes)
		start = end - maxAuditPreviewRunes
	}
	preview := string(runes[start:end])
	if start > 0 {
		preview = "…" + preview
	}
	if end < len(runes) {
		preview += "…"
	}
	return preview
}
