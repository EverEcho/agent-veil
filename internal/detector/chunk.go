package detector

import (
	"crypto/sha256"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
)

type ChunkedScanner struct {
	Scanner                  *Scanner
	ChunkBytes, OverlapBytes int
	mu                       sync.RWMutex
	cache                    map[[32]byte][]domain.Finding
}

func NewChunked(scanner *Scanner, chunkBytes, overlapBytes int) (*ChunkedScanner, error) {
	if scanner == nil || chunkBytes < 256 || overlapBytes < 32 || overlapBytes >= chunkBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "create chunk scanner", "invalid chunk or overlap size")
	}
	return &ChunkedScanner{Scanner: scanner, ChunkBytes: chunkBytes, OverlapBytes: overlapBytes, cache: map[[32]byte][]domain.Finding{}}, nil
}

func (s *ChunkedScanner) Scan(path, text string) ([]Match, error) {
	var all []Match
	for start := 0; start < len(text); {
		end := start + s.ChunkBytes
		if end > len(text) {
			end = len(text)
		} else {
			for end > start && end < len(text) && (text[end]&0xc0) == 0x80 {
				end--
			}
			if end == start {
				end = start + s.ChunkBytes
			}
		}
		chunk := text[start:end]
		hash := sha256.Sum256([]byte(chunk))
		findings, ok := s.cached(hash)
		if !ok {
			matches, err := s.Scanner.ScanChecked(path, chunk)
			if err != nil {
				return nil, err
			}
			findings = make([]domain.Finding, len(matches))
			for i := range matches {
				findings[i] = matches[i].Finding
				findings[i].Location.Path = ""
			}
			s.store(hash, findings)
		}
		for _, relative := range findings {
			finding := relative
			finding.Location.Path = path
			finding.Location.Start += start
			finding.Location.End += start
			all = append(all, Match{Finding: finding, Value: text[finding.Location.Start:finding.Location.End]})
		}
		if end == len(text) {
			break
		}
		start = end - s.OverlapBytes
		for start > 0 && (text[start]&0xc0) == 0x80 {
			start--
		}
	}
	return Merge(all), nil
}

func (s *ChunkedScanner) cached(hash [32]byte) ([]domain.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.cache[hash]
	return append([]domain.Finding(nil), value...), ok
}
func (s *ChunkedScanner) store(hash [32]byte, findings []domain.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[hash] = append([]domain.Finding(nil), findings...)
}
