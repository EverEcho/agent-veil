package pipeline

import (
	"strings"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
	veilstream "github.com/agentveil/agentveil/internal/stream"
)

const defaultStreamLookbehind = 512

type streamDocument struct {
	event    veilstream.Event
	document *protocol.Document
}

type SSEProcessor struct {
	protocol   domain.Protocol
	scanner    detector.ContentScanner
	vault      *redactor.Vault
	decoder    *veilstream.Decoder
	lookbehind int
	pending    []streamDocument
	closed     bool
}

func NewSSEProcessor(protocolType domain.Protocol, scanner detector.ContentScanner, vault *redactor.Vault, maxEventBytes, lookbehind int) (*SSEProcessor, error) {
	if scanner == nil || vault == nil || lookbehind < 128 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create SSE processor", "scanner, vault and a safe lookbehind are required")
	}
	decoder, err := veilstream.NewDecoder(maxEventBytes)
	if err != nil {
		return nil, err
	}
	return &SSEProcessor{protocol: protocolType, scanner: scanner, vault: vault, decoder: decoder, lookbehind: lookbehind}, nil
}

func (p *SSEProcessor) Push(chunk []byte) ([]byte, error) {
	if p.closed {
		return nil, domain.NewError(domain.ErrInvalidContract, "process SSE", "stream processor is closed")
	}
	events, err := p.decoder.Push(chunk)
	if err != nil {
		return nil, err
	}
	if err := p.append(events); err != nil {
		return nil, err
	}
	return p.flush(false)
}

func (p *SSEProcessor) Close() ([]byte, error) {
	if p.closed {
		return nil, domain.NewError(domain.ErrInvalidContract, "process SSE", "stream processor is closed")
	}
	p.closed = true
	if err := p.decoder.Close(); err != nil {
		return nil, err
	}
	return p.flush(true)
}

func (p *SSEProcessor) append(events []veilstream.Event) error {
	for _, event := range events {
		item := streamDocument{event: event}
		if event.Data != "" && strings.TrimSpace(event.Data) != "[DONE]" {
			document, err := protocol.ParseStreamEvent(p.protocol, []byte(event.Data))
			if err != nil {
				return err
			}
			item.document = document
		}
		p.pending = append(p.pending, item)
	}
	return nil
}

func (p *SSEProcessor) flush(final bool) ([]byte, error) {
	parts, references, eventEnds := p.parts()
	combined := strings.Join(parts, "")
	matches, err := p.scanner.ScanChecked("/response-stream", combined)
	if err != nil {
		return nil, err
	}
	if len(matches) > 0 {
		return nil, domain.NewError(domain.ErrPolicyBlocked, "process stream", "provider stream contains credential-shaped content")
	}
	emitCount := len(p.pending)
	if !final {
		safeText := len(combined) - p.lookbehind
		emitCount = 0
		for i, end := range eventEnds {
			if end == 0 || end <= safeText {
				emitCount = i + 1
			}
		}
		for emitCount > 0 && !safeCredentialBoundary(combined, eventEnds[emitCount-1]) {
			emitCount--
		}
		for emitCount > 0 && !safePlaceholderBoundary(p.pending[:emitCount]) {
			emitCount--
		}
	}
	if emitCount == 0 {
		return nil, nil
	}
	emittedParts := 0
	for emittedParts < len(references) && references[emittedParts][0] < emitCount {
		emittedParts++
	}
	restored, err := p.vault.RestoreParts(parts[:emittedParts])
	if err != nil {
		return nil, err
	}
	replacements := make([]map[string]string, emitCount)
	for i := 0; i < emittedParts; i++ {
		if restored[i] == parts[i] {
			continue
		}
		ref := references[i]
		if replacements[ref[0]] == nil {
			replacements[ref[0]] = map[string]string{}
		}
		replacements[ref[0]][p.pending[ref[0]].document.Fields[ref[1]].Path] = restored[i]
	}
	events := make([]veilstream.Event, emitCount)
	for i := 0; i < emitCount; i++ {
		events[i] = p.pending[i].event
		if p.pending[i].document == nil {
			continue
		}
		data, err := p.pending[i].document.Replace(replacements[i])
		if err != nil {
			return nil, err
		}
		events[i].Data = string(data)
	}
	p.pending = append(p.pending[:0], p.pending[emitCount:]...)
	return veilstream.Encode(events), nil
}

func (p *SSEProcessor) parts() ([]string, [][2]int, []int) {
	var parts []string
	var references [][2]int
	eventEnds := make([]int, len(p.pending))
	total := 0
	for i, item := range p.pending {
		if item.document != nil {
			for fieldIndex, field := range item.document.Fields {
				parts = append(parts, field.Text)
				references = append(references, [2]int{i, fieldIndex})
				total += len(field.Text)
			}
		}
		eventEnds[i] = total
	}
	return parts, references, eventEnds
}

func safeCredentialBoundary(text string, offset int) bool {
	if offset <= 0 || offset >= len(text) {
		return true
	}
	return !credentialByte(text[offset-1]) || !credentialByte(text[offset])
}

func credentialByte(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune("._~+/-=:@", rune(character))
}

func safePlaceholderBoundary(prefix []streamDocument) bool {
	left := streamText(prefix)
	marker := "[[VEIL_"
	for length := 1; length < len(marker) && length <= len(left); length++ {
		if strings.HasSuffix(left, marker[:length]) {
			return false
		}
	}
	if open := strings.LastIndex(left, marker); open >= 0 && !strings.Contains(left[open:], "]]") {
		return false
	}
	return true
}

func streamText(items []streamDocument) string {
	var text strings.Builder
	for _, item := range items {
		if item.document == nil {
			continue
		}
		for _, field := range item.document.Fields {
			text.WriteString(field.Text)
		}
	}
	return text.String()
}

func ProcessSSE(protocolType domain.Protocol, body []byte, scanner detector.ContentScanner, vault *redactor.Vault) ([]byte, error) {
	processor, err := NewSSEProcessor(protocolType, scanner, vault, len(body)+1, defaultStreamLookbehind)
	if err != nil {
		return nil, err
	}
	first, err := processor.Push(body)
	if err != nil {
		return nil, err
	}
	last, err := processor.Close()
	if err != nil {
		return nil, err
	}
	return append(first, last...), nil
}
