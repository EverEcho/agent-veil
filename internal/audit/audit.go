package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
)

var metadataScanner detector.ContentScanner = detector.NewDefault()

func WorkspaceReference(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "sha256:" + hex.EncodeToString(sum[:16])
}

func Marshal(event domain.AuditEvent, forbiddenValues ...string) ([]byte, error) {
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	text := string(payload)
	matches, err := detector.ScanContent(metadataScanner, "/audit", text)
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

func validateEvent(event domain.AuditEvent) error {
	if event.Timestamp.IsZero() || !event.Action.Valid() || event.FindingCount < 0 || event.FindingCount > 1_000_000 || event.LatencyMS < 0 || event.LatencyMS > 24*60*60*1000 || event.Severity != "" && !event.Severity.Valid() || event.Protocol != "" && !event.Protocol.Valid() || len(event.FindingTypes) > 256 {
		return domain.NewError(domain.ErrInvalidContract, "validate audit", "audit time, action, counts, or enums are invalid")
	}
	for _, value := range []string{event.SessionID, event.AgentID, event.SurfaceID, string(event.ErrorCode)} {
		if !validMetadataValue(value, 128) {
			return domain.NewError(domain.ErrInvalidContract, "validate audit", "audit identity metadata is invalid")
		}
	}
	if event.WorkspaceRef != "" && (!strings.HasPrefix(event.WorkspaceRef, "sha256:") || len(event.WorkspaceRef) != len("sha256:")+32 || !lowerHex(event.WorkspaceRef[len("sha256:"):])) {
		return domain.NewError(domain.ErrInvalidContract, "validate audit", "audit workspace reference is invalid")
	}
	if !validPreview(event.Preview) {
		return domain.NewError(domain.ErrInvalidContract, "validate audit", "audit preview is invalid")
	}
	for _, findingType := range event.FindingTypes {
		if !validMetadataValue(findingType, 128) {
			return domain.NewError(domain.ErrInvalidContract, "validate audit", "audit finding metadata is invalid")
		}
	}
	if len(event.FindingTypes) > 0 && event.FindingCount == 0 {
		return domain.NewError(domain.ErrInvalidContract, "validate audit", "audit finding types require a positive count")
	}
	return nil
}

func validPreview(value string) bool {
	if len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validMetadataValue(value string, limit int) bool {
	if value == "" {
		return true
	}
	if len(value) > limit {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
