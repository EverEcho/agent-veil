package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestAuditRejectsSensitiveContent(t *testing.T) {
	secret := "ghp_this_is_a_test_secret"
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
