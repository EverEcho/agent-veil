package pipeline

import (
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
)

func ProcessResponse(protocolType domain.Protocol, contentType string, body []byte, scanner detector.ContentScanner, vault *redactor.Vault) ([]byte, error) {
	document, err := protocol.ParseResponse(protocolType, contentType, body)
	if err != nil {
		return nil, err
	}
	replacements := map[string]string{}
	for _, field := range document.Fields {
		matches, scanErr := scanner.ScanChecked(field.Path, field.Text)
		if scanErr != nil {
			return nil, scanErr
		}
		if len(matches) > 0 {
			return nil, domain.NewError(domain.ErrPolicyBlocked, "process response", "provider response contains credential-shaped content")
		}
		restored, restoreErr := vault.Restore(field.Text)
		if restoreErr != nil {
			return nil, restoreErr
		}
		if restored != field.Text {
			replacements[field.Path] = restored
		}
	}
	return document.Replace(replacements)
}
