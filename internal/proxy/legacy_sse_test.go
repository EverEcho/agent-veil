package proxy

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/redactor"
)

func TestLegacySSEManagerBindsExactCapabilityAndOwnsVault(t *testing.T) {
	manager, err := NewLegacySSEManager(LegacySSELimits{MaxChannels: 2, MaxPostsPerChannel: 1})
	if err != nil {
		t.Fatal(err)
	}
	manager.random = bytes.NewReader(bytes.Repeat([]byte{1}, 32))
	vault := testLegacyVault(t)
	upstream, _ := url.Parse("https://mcp.example/messages?session=provider")
	binding, err := manager.Open("session-0123456789abcdef", "route-a", upstream, time.Now().Add(time.Minute), context.Background(), vault)
	if err != nil {
		t.Fatal(err)
	}
	upstream.Path = "/mutated"
	if binding.Upstream.Path != "/messages" || manager.Len() != 1 {
		t.Fatalf("binding was aliased or omitted: %+v", binding)
	}
	if _, _, ok := manager.Acquire(context.Background(), binding.ID, "other-session-123456", "route-a"); ok {
		t.Fatal("channel accepted a different session capability")
	}
	acquired, release, ok := manager.Acquire(context.Background(), binding.ID, binding.SessionID, binding.RouteID)
	if !ok || acquired.Upstream.String() != "https://mcp.example/messages?session=provider" || acquired.Vault != vault {
		t.Fatalf("exact channel binding unavailable: %+v", acquired)
	}
	blockedContext, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, ok := manager.Acquire(blockedContext, binding.ID, binding.SessionID, binding.RouteID); ok {
		t.Fatal("POST concurrency limit was bypassed")
	}
	release()
	release()
	if !manager.Close(binding.ID, binding.SessionID, binding.RouteID) || manager.Len() != 0 {
		t.Fatal("exact channel close failed")
	}
	var veilErr *domain.VeilError
	if _, err := vault.Store("pii", "secret"); !errors.As(err, &veilErr) || veilErr.Code != domain.ErrVaultDestroyed {
		t.Fatalf("closed channel retained its Vault: %v", err)
	}
}

func TestLegacySSEManagerIsBoundedAndRevocationFailsClosed(t *testing.T) {
	manager, err := NewLegacySSEManager(LegacySSELimits{MaxChannels: 1, MaxPostsPerChannel: 1})
	if err != nil {
		t.Fatal(err)
	}
	manager.random = bytes.NewReader(bytes.Repeat([]byte{2}, 64))
	sessionContext, revoke := context.WithCancel(context.Background())
	firstVault := testLegacyVault(t)
	upstream, _ := url.Parse("https://mcp.example/messages")
	first, err := manager.Open("session-0123456789abcdef", "route-a", upstream, time.Now().Add(time.Minute), sessionContext, firstVault)
	if err != nil {
		t.Fatal(err)
	}
	secondVault := testLegacyVault(t)
	if _, err := manager.Open("session-fedcba9876543210", "route-b", upstream, time.Now().Add(time.Minute), context.Background(), secondVault); err == nil {
		t.Fatal("legacy SSE channel capacity was bypassed")
	}
	secondVault.Destroy()
	revoke()
	if _, _, ok := manager.Acquire(context.Background(), first.ID, first.SessionID, first.RouteID); ok || manager.Len() != 0 {
		t.Fatal("revoked legacy SSE channel remained available")
	}
	var veilErr *domain.VeilError
	if _, err := firstVault.Store("pii", "secret"); !errors.As(err, &veilErr) || veilErr.Code != domain.ErrVaultDestroyed {
		t.Fatalf("revoked channel retained its Vault: %v", err)
	}
}

func TestLegacySSEManagerRejectsInvalidLimitsAndExpiredBindings(t *testing.T) {
	for _, limits := range []LegacySSELimits{{}, {MaxChannels: MaximumLegacySSEChannels + 1, MaxPostsPerChannel: 1}, {MaxChannels: 1, MaxPostsPerChannel: MaximumLegacySSEPostsPerChannel + 1}} {
		if _, err := NewLegacySSEManager(limits); err == nil {
			t.Fatalf("unsafe limits accepted: %+v", limits)
		}
	}
	manager := NewDefaultLegacySSEManager()
	for _, rawURL := range []string{"/relative", "https://user:secret@mcp.example/messages", "https://mcp.example/messages#fragment", "https://mcp.example/%2Fmessages"} {
		vault := testLegacyVault(t)
		upstream, _ := url.Parse(rawURL)
		if _, err := manager.Open("session-0123456789abcdef", "route-a", upstream, time.Now().Add(time.Minute), context.Background(), vault); err == nil {
			t.Fatalf("unsafe dynamic POST URL accepted: %q", rawURL)
		}
		vault.Destroy()
	}
	vault := testLegacyVault(t)
	upstream, _ := url.Parse("https://mcp.example/messages")
	if _, err := manager.Open("session-0123456789abcdef", "route-a", upstream, time.Now().Add(-time.Second), context.Background(), vault); err == nil {
		t.Fatal("expired legacy SSE channel was accepted")
	}
	vault.Destroy()
}

func testLegacyVault(t *testing.T) *redactor.Vault {
	t.Helper()
	vault, err := redactor.NewVault(bytes.Repeat([]byte{9}, 32), redactor.Limits{MaxEntries: 16, MaxOriginalBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	return vault
}
