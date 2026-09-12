package pipeline

import (
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
	veilstream "github.com/agentveil/agentveil/internal/stream"
	"strings"
)

func ProcessSSE(protocolType domain.Protocol, body []byte, scanner *detector.Scanner, vault *redactor.Vault) ([]byte, error) {
	decoder, err := veilstream.NewDecoder(len(body) + 1)
	if err != nil {
		return nil, err
	}
	events, err := decoder.Push(body)
	if err != nil {
		return nil, err
	}
	if err := decoder.Close(); err != nil {
		return nil, err
	}
	documents := make([]*protocol.Document, len(events))
	var parts []string
	var references [][2]int
	for i, event := range events {
		if event.Data == "" || strings.TrimSpace(event.Data) == "[DONE]" {
			continue
		}
		document, parseErr := protocol.ParseStreamEvent(protocolType, []byte(event.Data))
		if parseErr != nil {
			return nil, parseErr
		}
		documents[i] = document
		for fieldIndex, field := range document.Fields {
			parts = append(parts, field.Text)
			references = append(references, [2]int{i, fieldIndex})
		}
	}
	combined := strings.Join(parts, "")
	matches, scanErr := scanner.ScanChecked("/response-stream", combined)
	if scanErr != nil {
		return nil, scanErr
	}
	if len(matches) > 0 {
		return nil, domain.NewError(domain.ErrPolicyBlocked, "process stream", "provider stream contains credential-shaped content")
	}
	restored, err := vault.RestoreParts(parts)
	if err != nil {
		return nil, err
	}
	replacements := make([]map[string]string, len(events))
	for i, ref := range references {
		if restored[i] == parts[i] {
			continue
		}
		if replacements[ref[0]] == nil {
			replacements[ref[0]] = map[string]string{}
		}
		replacements[ref[0]][documents[ref[0]].Fields[ref[1]].Path] = restored[i]
	}
	for i, document := range documents {
		if document == nil {
			continue
		}
		data, replaceErr := document.Replace(replacements[i])
		if replaceErr != nil {
			return nil, replaceErr
		}
		events[i].Data = string(data)
	}
	return veilstream.Encode(events), nil
}
