package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
)

var metadataScanner detector.ContentScanner = detector.NewDefault()

func WorkspaceReference(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "sha256:" + hex.EncodeToString(sum[:16])
}

func Marshal(event domain.AuditEvent, forbiddenValues ...string) ([]byte, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	text := string(payload)
	matches, err := metadataScanner.ScanChecked("/audit", text)
	if err != nil {
		return nil, domain.NewError(domain.ErrDetectorFailure, "marshal audit", "audit leak scan failed")
	}
	if len(matches) != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "marshal audit", "audit payload contains detected sensitive content")
	}
	for _, value := range forbiddenValues {
		if value != "" && strings.Contains(text, value) {
			return nil, domain.NewError(domain.ErrInvalidContract, "marshal audit", "audit payload contains forbidden sensitive content")
		}
	}
	return payload, nil
}
