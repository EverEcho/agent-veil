package stream

import (
	"strings"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/redactor"
)

// Guard delays a bounded response tail so credentials and placeholders split
// across provider events cannot be emitted before they are classified.
type Guard struct {
	pending    string
	lookbehind int
	maxBuffer  int
	scanner    detector.ContentScanner
	vault      *redactor.Vault
}

const (
	MaxResponseLookbehindBytes = 64 << 10
	MaxResponseBufferBytes     = 1 << 20
)

func NewGuard(scanner detector.ContentScanner, vault *redactor.Vault, lookbehind, maxBuffer int) (*Guard, error) {
	if scanner == nil || vault == nil || lookbehind < 128 || lookbehind > MaxResponseLookbehindBytes || maxBuffer < lookbehind || maxBuffer > MaxResponseBufferBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "create response guard", "invalid detector, vault or buffer limits")
	}
	return &Guard{scanner: scanner, vault: vault, lookbehind: lookbehind, maxBuffer: maxBuffer}, nil
}

func (g *Guard) Push(text string) (string, error) {
	if len(text) > g.maxBuffer-len(g.pending) {
		return "", domain.NewError(domain.ErrInvalidContract, "guard response", "response safety buffer limit exceeded")
	}
	g.pending += text
	if matches, err := detector.ScanContent(g.scanner, "/response", g.pending); err != nil {
		return "", err
	} else if len(matches) > 0 {
		return "", domain.NewError(domain.ErrPolicyBlocked, "guard response", "provider response contains credential-shaped content")
	}
	cut := len(g.pending) - g.lookbehind
	if cut <= 0 {
		return "", nil
	}
	if open := strings.LastIndex(g.pending[:cut], "[[VEIL_"); open >= 0 && !strings.Contains(g.pending[open:cut], "]]") {
		cut = open
	}
	for cut > 0 && cut < len(g.pending) && !utf8.RuneStart(g.pending[cut]) {
		cut--
	}
	output, err := g.vault.Restore(g.pending[:cut])
	if err != nil {
		return "", err
	}
	g.pending = g.pending[cut:]
	return output, nil
}

func (g *Guard) Close() (string, error) {
	if matches, err := detector.ScanContent(g.scanner, "/response", g.pending); err != nil {
		return "", err
	} else if len(matches) > 0 {
		return "", domain.NewError(domain.ErrPolicyBlocked, "guard response", "provider response contains credential-shaped content")
	}
	output, err := g.vault.Restore(g.pending)
	g.pending = ""
	return output, err
}
