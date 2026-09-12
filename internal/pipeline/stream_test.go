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

func TestSSEProcessorEmitsSafeEventsBeforeClose(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	processor, err := NewSSEProcessor(domain.ProtocolOpenAIResponses, detector.NewDefault(), vault, 4096, 128)
	if err != nil {
		t.Fatal(err)
	}
	event := func(value string) []byte {
		payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": value})
		return []byte("data: " + string(payload) + "\n\n")
	}
	if output, err := processor.Push(event(strings.Repeat("a", 100))); err != nil || len(output) != 0 {
		t.Fatalf("first push output=%q err=%v", output, err)
	}
	if output, err := processor.Push(event(strings.Repeat("b", 100))); err != nil || len(output) != 0 {
		t.Fatalf("second push output=%q err=%v", output, err)
	}
	output, err := processor.Push(event(strings.Repeat("c", 100)))
	if err != nil || !strings.Contains(string(output), strings.Repeat("a", 100)) || strings.Contains(string(output), strings.Repeat("b", 100)) {
		t.Fatalf("safe prefix was not emitted incrementally: %q %v", output, err)
	}
	tail, err := processor.Close()
	if err != nil || !strings.Contains(string(tail), strings.Repeat("b", 100)) || !strings.Contains(string(tail), strings.Repeat("c", 100)) {
		t.Fatalf("tail=%q err=%v", tail, err)
	}
}

func TestSSEProcessorBlocksCredentialSplitAcrossEvents(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	processor, _ := NewSSEProcessor(domain.ProtocolOpenAIResponses, detector.NewDefault(), vault, 4096, 128)
	event := func(value string) []byte {
		payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": value})
		return []byte("data: " + string(payload) + "\n\n")
	}
	if output, err := processor.Push(event("leak ghp_abcdefghij")); err != nil || len(output) != 0 {
		t.Fatalf("first fragment output=%q err=%v", output, err)
	}
	if output, err := processor.Push(event("klmnopqrstuvwxyz" + strings.Repeat("x", 200))); err == nil || len(output) != 0 {
		t.Fatalf("split credential was emitted: %q err=%v", output, err)
	}
}
