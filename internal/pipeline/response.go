package pipeline

import (
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
)

type ResponseResult struct {
	Body     []byte
	Findings []domain.Finding
}

func ProcessResponse(protocolType domain.Protocol, contentType string, body []byte, scanner detector.ContentScanner, vault *redactor.Vault) ([]byte, error) {
	result, err := ProcessResponseDetailed(protocolType, contentType, body, scanner, vault)
	return result.Body, err
}

func ProcessResponseDetailed(protocolType domain.Protocol, contentType string, body []byte, scanner detector.ContentScanner, vault *redactor.Vault) (ResponseResult, error) {
	var result ResponseResult
	document, err := protocol.ParseResponse(protocolType, contentType, body)
	if err != nil {
		return result, err
	}
	replacements := map[string]string{}
	for _, field := range document.Fields {
		matches, scanErr := detector.ScanContent(scanner, field.Path, field.Text)
		if scanErr != nil {
			return result, scanErr
		}
		if len(matches) > 0 {
			for _, match := range matches {
				result.Findings = append(result.Findings, match.Finding)
			}
			return result, domain.NewError(domain.ErrPolicyBlocked, "process response", "provider response contains credential-shaped content")
		}
		restored, restoreErr := vault.Restore(field.Text)
		if restoreErr != nil {
			return result, restoreErr
		}
		if restored != field.Text {
			replacements[field.Path] = restored
		}
	}
	result.Body, err = document.Replace(replacements)
	return result, err
}
