package audit

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestAuditRejectsSensitiveContent(t *testing.T) {
	secret := "ghp_this_is_a_test_secret"
	if canary := os.Getenv("VEIL_TEST_LEAK_CANARY"); canary != "" {
		secret = canary
	}
	event := domain.AuditEvent{Timestamp: time.Now(), AgentID: secret, Action: domain.ActionBlock}
	if _, err := Marshal(event, secret); err == nil {
		t.Fatal("audit marshal accepted forbidden sensitive content")
	}
	ref := WorkspaceReference("/private/customer/project")
	if !strings.HasPrefix(ref, "sha256:") || strings.Contains(ref, "customer") {
		t.Fatalf("workspace reference is not safely hashed: %s", ref)
	}
}

func TestAuditLeakScanRejectsSensitiveMetadataByDefault(t *testing.T) {
	for _, value := range []string{"dev@example.com", "ghp_abcdefghijklmnopqrstuvwxyz"} {
		event := domain.AuditEvent{Timestamp: time.Now(), AgentID: value, Action: domain.ActionBlock}
		if _, err := Marshal(event); err == nil {
			t.Fatalf("audit marshal accepted sensitive metadata %q", value)
		}
	}
}

func TestAuditAcceptsOnlyBoundedSensitiveFreePreview(t *testing.T) {
	safe := domain.AuditEvent{Timestamp: time.Now(), Action: domain.ActionRedact, FindingCount: 1, FindingTypes: []string{"pii.email"}, Preview: "这个是我邮箱 ***，请逐字返回"}
	payload, err := Marshal(safe)
	if err != nil || !strings.Contains(string(payload), `"preview":"这个是我邮箱 ***，请逐字返回"`) {
		t.Fatalf("safe preview rejected: %s %v", payload, err)
	}
	for _, preview := range []string{"这个是我邮箱 dev@example.com", "line one\nline two", strings.Repeat("x", 1025)} {
		unsafe := safe
		unsafe.Preview = preview
		if _, err := Marshal(unsafe); err == nil {
			t.Fatalf("unsafe preview accepted: %q", preview)
		}
	}
}

func TestAuditRejectsInvalidMetadataAndBounds(t *testing.T) {
	now := time.Now().UTC()
	for _, event := range []domain.AuditEvent{
		{Action: domain.ActionBlock},
		{Timestamp: now, Action: domain.Action("invalid")},
		{Timestamp: now, Action: domain.ActionBlock, FindingCount: -1},
		{Timestamp: now, Action: domain.ActionBlock, LatencyMS: -1},
		{Timestamp: now, Action: domain.ActionBlock, AgentID: "unsafe/path"},
		{Timestamp: now, Action: domain.ActionBlock, FindingTypes: []string{"pii.email"}},
	} {
		if _, err := Marshal(event); err == nil {
			t.Fatalf("invalid audit event was accepted: %+v", event)
		}
	}
}
