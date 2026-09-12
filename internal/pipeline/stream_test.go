package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/redactor"
	veilstream "github.com/agentveil/agentveil/internal/stream"
)

func TestSSEPlaceholderCrossesEventsWithoutTouchingSignature(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	placeholder, _ := vault.Store("email", "dev@example.com")
	first, _ := json.Marshal(map[string]any{"type": "content_block_delta", "delta": map[string]any{"type": "text_delta", "text": placeholder[:12]}, "signature": placeholder})
	second, _ := json.Marshal(map[string]any{"type": "content_block_delta", "delta": map[string]any{"type": "text_delta", "text": placeholder[12:]}})
	body := []byte("data: " + string(first) + "\n\ndata: " + string(second) + "\n\n")
	result, err := ProcessSSE(domain.ProtocolAnthropic, body, detector.NewDefault(), vault)
	if err != nil {
		t.Fatal(err)
	}
	decoder, _ := veilstream.NewDecoder(4096)
	events, _ := decoder.Push(result)
	var combined string
	for _, event := range events {
		var object map[string]any
		_ = json.Unmarshal([]byte(event.Data), &object)
		if signature, ok := object["signature"].(string); ok && signature != placeholder {
			t.Fatal("signature was modified")
		}
		if delta, ok := object["delta"].(map[string]any); ok {
			combined += delta["text"].(string)
		}
	}
	if combined != "dev@example.com" {
		t.Fatalf("combined=%q stream=%s", combined, result)
	}
}
