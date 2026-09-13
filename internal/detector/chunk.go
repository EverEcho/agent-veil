package detector

import (
	"crypto/sha256"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/domain"
)

type ChunkedScanner struct {
	Scanner                  *Scanner
	ChunkBytes, OverlapBytes int
	mu                       sync.RWMutex
	cache                    map[[32]byte][]domain.Finding
	cacheOrder               [][32]byte
	maxCacheEntries          int
}

const (
	DefaultChunkBytes        = 64 << 10
	DefaultOverlapBytes      = 4 << 10
	defaultChunkCacheEntries = 1024
	MaxChunkBytes            = 1 << 20
	MaxOverlapBytes          = 256 << 10
	MaxChunkCacheEntries     = 16 << 10
)

func NewDefaultChunked() (*ChunkedScanner, error) {
	return NewChunked(NewDefault(), DefaultChunkBytes, DefaultOverlapBytes)
}

func NewChunked(scanner *Scanner, chunkBytes, overlapBytes int) (*ChunkedScanner, error) {
	return NewChunkedWithCacheLimit(scanner, chunkBytes, overlapBytes, defaultChunkCacheEntries)
}

func NewChunkedWithCacheLimit(scanner *Scanner, chunkBytes, overlapBytes, maxCacheEntries int) (*ChunkedScanner, error) {
	if scanner == nil || chunkBytes < 256 || chunkBytes > MaxChunkBytes || overlapBytes < 32 || overlapBytes > MaxOverlapBytes || overlapBytes >= chunkBytes || maxCacheEntries < 1 || maxCacheEntries > MaxChunkCacheEntries {
		return nil, domain.NewError(domain.ErrInvalidContract, "create chunk scanner", "invalid chunk, overlap, or cache limit")
	}
	return &ChunkedScanner{
		Scanner:         scanner,
		ChunkBytes:      chunkBytes,
		OverlapBytes:    overlapBytes,
		cache:           map[[32]byte][]domain.Finding{},
		cacheOrder:      make([][32]byte, 0, maxCacheEntries),
		maxCacheEntries: maxCacheEntries,
	}, nil
}

func (s *ChunkedScanner) Scan(path, text string) ([]Match, error) {
	var all []Match
	for start := 0; start < len(text); {
		end := stableChunkEnd(text, start, s.ChunkBytes, s.OverlapBytes)
		chunk := text[start:end]
		hash := chunkCacheKey(path, chunk)
		findings, ok := s.cached(hash)
		if !ok {
			matches, err := ScanContent(s.Scanner, path, chunk)
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

func stableChunkEnd(text string, start, chunkBytes, overlapBytes int) int {
	hardEnd := start + chunkBytes
	if hardEnd >= len(text) {
		return len(text)
	}
	for hardEnd > start && !utf8.RuneStart(text[hardEnd]) {
		hardEnd--
	}
	if hardEnd <= start+overlapBytes {
		return hardEnd
	}

	searchStart := hardEnd - overlapBytes
	for searchStart > start && !utf8.RuneStart(text[searchStart]) {
		searchStart--
	}
	lastNewline, lastSpace := 0, 0
	for offset, r := range text[searchStart:hardEnd] {
		end := searchStart + offset + utf8.RuneLen(r)
		if end <= start+overlapBytes {
			continue
		}
		if r == '\n' || r == '\r' {
			lastNewline = end
		} else if unicode.IsSpace(r) {
			lastSpace = end
		}
	}
	if lastNewline != 0 {
		return lastNewline
	}
	if lastSpace != 0 {
		return lastSpace
	}
	return hardEnd
}

func (s *ChunkedScanner) ScanChecked(path, text string) ([]Match, error) {
	return s.Scan(path, text)
}

func chunkCacheKey(path, chunk string) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(path))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(chunk))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
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
	if _, exists := s.cache[hash]; exists {
		return
	}
	if len(s.cacheOrder) == s.maxCacheEntries {
		delete(s.cache, s.cacheOrder[0])
		copy(s.cacheOrder, s.cacheOrder[1:])
		s.cacheOrder = s.cacheOrder[:len(s.cacheOrder)-1]
	}
	s.cache[hash] = append([]domain.Finding(nil), findings...)
	s.cacheOrder = append(s.cacheOrder, hash)
}
