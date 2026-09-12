package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

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
	for _, value := range forbiddenValues {
		if value != "" && strings.Contains(text, value) {
			return nil, domain.NewError(domain.ErrInvalidContract, "marshal audit", "audit payload contains forbidden sensitive content")
		}
	}
	return payload, nil
}
