package stream

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/redactor"
)

func TestSSERandomChunkingPreservesEvents(t *testing.T) {
	source := "event: delta\ndata: {\"text\":\"你好\"}\n\nid: 2\ndata: done\n\n"
	for seed := int64(0); seed < 50; seed++ {
		decoder, _ := NewDecoder(4096)
		random := rand.New(rand.NewSource(seed))
		var events []Event
		for offset := 0; offset < len(source); {
			size := 1 + random.Intn(7)
			if offset+size > len(source) {
				size = len(source) - offset
			}
			got, err := decoder.Push([]byte(source[offset : offset+size]))
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, got...)
			offset += size
		}
		if err := decoder.Close(); err != nil || len(events) != 2 || events[0].Event != "delta" || events[1].Data != "done" {
			t.Fatalf("seed %d: %+v %v", seed, events, err)
		}
	}
}

func TestGuardRestoresSplitPlaceholderAndBlocksSplitSecret(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 5, MaxOriginalBytes: 100})
	placeholder, _ := vault.Store("email", "dev@example.com")
	guard, _ := NewGuard(detector.NewDefault(), vault, 128, 4096)
	var output string
	for _, piece := range []string{"answer ", placeholder[:10], placeholder[10:]} {
		part, err := guard.Push(piece)
		if err != nil {
			t.Fatal(err)
		}
		output += part
	}
	tail, err := guard.Close()
	if err != nil {
		t.Fatal(err)
	}
	output += tail
	if output != "answer dev@example.com" {
		t.Fatalf("restored output=%q", output)
	}
	guard, _ = NewGuard(detector.NewDefault(), vault, 128, 4096)
	if _, err := guard.Push("leak ghp_abcdefghij"); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Push("klmnopqrstuvwxyz"); err == nil {
		t.Fatal("split credential was not blocked")
	}
}

func TestStreamingPrimitivesRejectUnboundedConfiguration(t *testing.T) {
	if _, err := NewDecoder(MaxSSEEventBytes + 1); err == nil {
		t.Fatal("unbounded SSE event limit accepted")
	}
	decoder, err := NewDecoder(16 << 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Push([]byte(strings.Repeat("\n\n", MaxSSEEventsPerPush+1))); err == nil {
		t.Fatal("unbounded SSE event batch accepted")
	}
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	if _, err := NewGuard(detector.NewDefault(), vault, MaxResponseLookbehindBytes+1, MaxResponseBufferBytes); err == nil {
		t.Fatal("unbounded response lookbehind accepted")
	}
	if _, err := NewGuard(detector.NewDefault(), vault, 128, MaxResponseBufferBytes+1); err == nil {
		t.Fatal("unbounded response buffer accepted")
	}
	guard, _ := NewGuard(detector.NewDefault(), vault, 128, 256)
	if _, err := guard.Push(strings.Repeat("x", 257)); err == nil || len(guard.pending) != 0 {
		t.Fatalf("oversized push was buffered: pending=%d err=%v", len(guard.pending), err)
	}
}
