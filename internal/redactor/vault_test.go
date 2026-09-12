package redactor

import (
	"errors"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestPlaceholderStableWithinSessionAndDifferentAcrossSessions(t *testing.T) {
	v1, _ := NewVault([]byte(strings.Repeat("a", 32)), Limits{MaxEntries: 5, MaxOriginalBytes: 100})
	v2, _ := NewVault([]byte(strings.Repeat("b", 32)), Limits{MaxEntries: 5, MaxOriginalBytes: 100})
	p1, err := v1.Store("pii.cn.phone", "13800138000")
	if err != nil {
		t.Fatal(err)
	}
	p1Again, _ := v1.Store("pii.cn.phone", "13800138000")
	p2, _ := v2.Store("pii.cn.phone", "13800138000")
	if p1 != p1Again || p1 == p2 {
		t.Fatalf("unexpected placeholder stability: %q %q %q", p1, p1Again, p2)
	}
	restored, err := v1.Restore("call " + p1)
	if err != nil || restored != "call 13800138000" {
		t.Fatalf("restore failed: %q %v", restored, err)
	}
}

func TestVaultFailsClosedAtCapacityAndAfterDestroy(t *testing.T) {
	v, _ := NewVault([]byte(strings.Repeat("a", 32)), Limits{MaxEntries: 1, MaxOriginalBytes: 10})
	if _, err := v.Store("email", "a@b.co"); err != nil {
		t.Fatal(err)
	}
	_, err := v.Store("phone", "123")
	var veilErr *domain.VeilError
	if !errors.As(err, &veilErr) || veilErr.Code != domain.ErrVaultFull {
		t.Fatalf("expected vault full, got %v", err)
	}
	v.Destroy()
	if _, err := v.Store("email", "x@y.co"); err == nil {
		t.Fatal("destroyed vault accepted a value")
	}
}

func TestRestoreRejectsUnknownAndMalformedPlaceholder(t *testing.T) {
	v, _ := NewVault([]byte(strings.Repeat("a", 32)), Limits{MaxEntries: 1, MaxOriginalBytes: 20})
	if _, err := v.Restore("[[VEIL_EMAIL_0123456789ABCDEF]]"); err == nil {
		t.Fatal("unknown placeholder was accepted")
	}
	if _, err := v.Restore("[[VEIL_EMAIL_INCOMPLETE"); err == nil {
		t.Fatal("malformed placeholder was accepted")
	}
}
