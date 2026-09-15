package pipeline

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
	veilstream "github.com/agentveil/agentveil/internal/stream"
)

func TestSSEProtocolMatrixRestoresFragmentedPlaceholders(t *testing.T) {
	tests := []struct {
		name     string
		protocol domain.Protocol
		payload  func(string) any
	}{
		{"openai-chat", domain.ProtocolOpenAIChat, func(value string) any {
			return map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": value}}}}
		}},
		{"openai-responses", domain.ProtocolOpenAIResponses, func(value string) any {
			return map[string]any{"type": "response.output_text.delta", "delta": value}
		}},
		{"anthropic", domain.ProtocolAnthropic, func(value string) any {
			return map[string]any{"type": "content_block_delta", "delta": map[string]any{"type": "text_delta", "text": value}}
		}},
		{"gemini", domain.ProtocolGemini, func(value string) any {
			return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": value}}}}}}
		}},
		{"mcp-http", domain.ProtocolMCPHTTP, func(value string) any {
			return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": value}}}}
		}},
		{"mcp-streamable", domain.ProtocolMCPStreamable, func(value string) any {
			return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": value}}}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
			placeholder, _ := vault.Store("email", "dev@example.com")
			payload, _ := json.Marshal(test.payload(placeholder))
			stream := []byte("data: " + string(payload) + "\n\n")
			processor, err := NewSSEProcessor(test.protocol, detector.NewDefault(), vault, 4096, 128)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			for _, fragment := range stream {
				part, err := processor.Push([]byte{fragment})
				if err != nil {
					t.Fatal(err)
				}
				output.Write(part)
			}
			tail, err := processor.Close()
			if err != nil {
				t.Fatal(err)
			}
			output.Write(tail)
			if !strings.Contains(output.String(), "dev@example.com") || strings.Contains(output.String(), placeholder) {
				t.Fatalf("placeholder was not restored: %s", output.String())
			}
		})
	}
}

func TestSSEProtocolMatrixBlocksNewCredentials(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz"
	for _, test := range []struct {
		protocol domain.Protocol
		payload  any
	}{
		{domain.ProtocolOpenAIChat, map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": secret}}}}},
		{domain.ProtocolOpenAIResponses, map[string]any{"delta": secret}},
		{domain.ProtocolAnthropic, map[string]any{"delta": map[string]any{"text": secret}}},
		{domain.ProtocolGemini, map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": secret}}}}}}},
		{domain.ProtocolMCPHTTP, map[string]any{"result": map[string]any{"value": secret}}},
		{domain.ProtocolMCPStreamable, map[string]any{"result": map[string]any{"value": secret}}},
	} {
		payload, _ := json.Marshal(test.payload)
		body := []byte("data: " + string(payload) + "\n\n")
		vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
		if _, err := ProcessSSE(test.protocol, body, detector.NewDefault(), vault); err == nil {
			t.Fatalf("protocol %s emitted a new credential", test.protocol)
		}
	}
}

func TestSSEProcessorReportsBlockedFindingMetadata(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	processor, _ := NewSSEProcessor(domain.ProtocolOpenAIResponses, detector.NewDefault(), vault, 4096, 128)
	payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": "ghp_abcdefghijklmnopqrstuvwxyz"})
	if output, err := processor.Push([]byte("data: " + string(payload) + "\n\n")); err == nil || len(output) != 0 {
		t.Fatalf("credential was not blocked: output=%q err=%v", output, err)
	}
	result := processor.Result()
	if len(result.Findings) != 1 || result.Findings[0].Category != "secret.github_pat" || len(result.Actions) != 1 || result.Actions[0] != domain.ActionBlock {
		t.Fatalf("result=%+v", result)
	}
}

func TestSSEProcessorRedactsProviderFindingAndPreservesCompletion(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	processor, err := NewSSEProcessorWithPolicy(Context{}, domain.ProtocolOpenAIResponses, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault, 4096, 128)
	if err != nil {
		t.Fatal(err)
	}
	delta, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": "ghp_abcdefghijklmnopqrstuvwxyz"})
	completed, _ := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{"status": "completed"}})
	stream := []byte("data: " + string(delta) + "\n\ndata: " + string(completed) + "\n\n")
	first, err := processor.Push(stream)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := processor.Close()
	if err != nil {
		t.Fatal(err)
	}
	output := string(append(first, tail...))
	if strings.Contains(output, "ghp_") || !strings.Contains(output, "[REDACTED]") || !strings.Contains(output, "response.completed") {
		t.Fatalf("redacted stream lost its terminal event: %s", output)
	}
	result := processor.Result()
	if len(result.Findings) != 1 || len(result.Actions) != 1 || result.Actions[0] != domain.ActionRedact {
		t.Fatalf("result=%+v", result)
	}
}

func TestResponsesSSEPreservesEncryptedReasoningUnchanged(t *testing.T) {
	const opaque = "ghp_abcdefghijklmnopqrstuvwxyz"
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	processor, err := NewSSEProcessorWithPolicy(Context{}, domain.ProtocolOpenAIResponses, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault, 4096, 128)
	if err != nil {
		t.Fatal(err)
	}
	done, _ := json.Marshal(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "reasoning", "id": "rs_test", "encrypted_content": opaque, "summary": []any{}}})
	completed, _ := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{"output": []any{map[string]any{"type": "reasoning", "id": "rs_test", "encrypted_content": opaque, "summary": []any{}}}}})
	first, err := processor.Push([]byte("data: " + string(done) + "\n\ndata: " + string(completed) + "\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	tail, err := processor.Close()
	if err != nil {
		t.Fatal(err)
	}
	output := string(append(first, tail...))
	result := processor.Result()
	if strings.Count(output, opaque) != 2 || strings.Contains(output, "[REDACTED]") || len(result.Findings) != 0 {
		t.Fatalf("encrypted reasoning was inspected or changed: output=%s result=%+v", output, result)
	}
}

func TestSSEProcessorRestoresHyphenatedPlaceholderAcrossEvents(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	placeholder, _ := vault.Store("pii.email", "qa-person@example.com")
	hyphenated := strings.Join(strings.Split(placeholder, ""), "-")
	processor, _ := NewSSEProcessorWithPolicy(Context{}, domain.ProtocolOpenAIResponses, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault, 4096, 128)
	var stream bytes.Buffer
	for _, character := range strings.Split(hyphenated, "") {
		payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": character})
		stream.WriteString("data: " + string(payload) + "\n\n")
	}
	completed, _ := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{"status": "completed"}})
	stream.WriteString("data: " + string(completed) + "\n\n")
	first, err := processor.Push(stream.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tail, err := processor.Close()
	if err != nil {
		t.Fatal(err)
	}
	output := string(append(first, tail...))
	if !strings.Contains(output, "q-a---p-e-r-s-o-n-@-e-x-a-m-p-l-e-.-c-o-m") || strings.Contains(output, "V-E-I-L") || !strings.Contains(output, "response.completed") {
		t.Fatalf("hyphenated placeholder was not restored across events: %s", output)
	}
}

func TestSSEProcessorRestoresHyphenatedPlaceholderFromResponsesDoneEvents(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	placeholder, _ := vault.Store("pii.email", "qa-person@example.com")
	hyphenated := strings.Join(strings.Split(placeholder, ""), "-")
	processor, _ := NewSSEProcessorWithPolicy(Context{}, domain.ProtocolOpenAIResponses, detector.NewDefault(), policy.Engine{Default: domain.ActionRedact}, vault, 1<<20, 128)
	done, _ := json.Marshal(map[string]any{"type": "response.output_text.done", "text": hyphenated})
	completed, _ := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": hyphenated}}}}}})
	stream := []byte("data: " + string(done) + "\n\ndata: " + string(completed) + "\n\n")
	first, err := processor.Push(stream)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := processor.Close()
	if err != nil {
		t.Fatal(err)
	}
	output := string(append(first, tail...))
	if strings.Contains(output, "V-E-I-L") || strings.Count(output, "q-a---p-e-r-s-o-n-@-e-x-a-m-p-l-e-.-c-o-m") != 2 || !strings.Contains(output, "response.completed") {
		t.Fatalf("Responses done events were not restored: %s", output)
	}
}

func TestSSEProtocolErrorsCannotEchoSensitiveContent(t *testing.T) {
	body := []byte("data: {\"error\":{\"message\":\"request contained dev@example.com\"}}\n\n")
	for _, protocolType := range []domain.Protocol{domain.ProtocolOpenAIChat, domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic, domain.ProtocolGemini, domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable} {
		vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
		if _, err := ProcessSSE(protocolType, body, detector.NewDefault(), vault); err == nil {
			t.Fatalf("protocol %s returned a sensitive stream error payload", protocolType)
		}
	}
}

func TestUnknownSSEEnvelopeIsNeverEmitted(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	body := []byte("data: {\"future_output\":\"dev@example.com\"}\n\n")
	result, err := ProcessSSE(domain.ProtocolOpenAIResponses, body, detector.NewDefault(), vault)
	if err == nil || len(result) != 0 {
		t.Fatalf("unknown stream envelope emitted: result=%q err=%v", result, err)
	}
}

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
	firstText := strings.Repeat("a", 99) + " "
	secondText := strings.Repeat("b", 99) + " "
	thirdText := strings.Repeat("c", 99) + " "
	if output, err := processor.Push(event(firstText)); err != nil || len(output) != 0 {
		t.Fatalf("first push output=%q err=%v", output, err)
	}
	if output, err := processor.Push(event(secondText)); err != nil || len(output) != 0 {
		t.Fatalf("second push output=%q err=%v", output, err)
	}
	output, err := processor.Push(event(thirdText))
	if err != nil || !strings.Contains(string(output), firstText) || strings.Contains(string(output), secondText) {
		t.Fatalf("safe prefix was not emitted incrementally: %q %v", output, err)
	}
	tail, err := processor.Close()
	if err != nil || !strings.Contains(string(tail), secondText) || !strings.Contains(string(tail), thirdText) {
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

func TestSSEProcessorDoesNotFlushLongUnfinishedCredentialToken(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	processor, _ := NewSSEProcessor(domain.ProtocolOpenAIResponses, detector.NewDefault(), vault, 4096, 512)
	event := func(value string) []byte {
		payload, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": value})
		return []byte("data: " + string(payload) + "\n\n")
	}
	firstSegment := "eyJ" + strings.Repeat("a", 600)
	if output, err := processor.Push(event(firstSegment)); err != nil || len(output) != 0 {
		t.Fatalf("first segment output=%q err=%v", output, err)
	}
	if output, err := processor.Push(event(strings.Repeat("b", 600))); err != nil || len(output) != 0 {
		t.Fatalf("unfinished credential prefix leaked after lookbehind: bytes=%d err=%v", len(output), err)
	}
	if output, err := processor.Push(event(".payload1.signature1")); err == nil || len(output) != 0 {
		t.Fatalf("completed long JWT was emitted: bytes=%d err=%v", len(output), err)
	}
}

func TestSSEProcessorRejectsUnboundedLookbehindAndPendingEvents(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	if _, err := NewSSEProcessor(domain.ProtocolOpenAIResponses, detector.NewDefault(), vault, 4096, veilstream.MaxResponseLookbehindBytes+1); err == nil {
		t.Fatal("unbounded stream lookbehind accepted")
	}
	processor, err := NewSSEProcessor(domain.ProtocolOpenAIResponses, detector.NewDefault(), vault, veilstream.MaxSSEEventBytes, 128)
	if err != nil {
		t.Fatal(err)
	}
	events := make([]veilstream.Event, MaxPendingStreamEvents+1)
	if err := processor.append(events); err == nil || len(processor.pending) != 0 {
		t.Fatalf("unbounded pending events accepted: pending=%d err=%v", len(processor.pending), err)
	}
}
