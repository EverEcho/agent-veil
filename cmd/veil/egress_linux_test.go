//go:build linux

package main

import (
	"errors"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
)

func TestProtectedCoreLocalEndpointRequiresExactLoopbackAuthority(t *testing.T) {
	endpoint, err := protectedCoreLocalEndpoint("http://127.0.0.1:48123")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Transport != egress.TransportTCP || endpoint.Host != "127.0.0.1" || endpoint.Port != 48123 {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	for _, invalid := range []string{"https://127.0.0.1:48123", "http://192.0.2.1:48123", "http://127.0.0.1:0", "http://localhost:48123"} {
		if endpoint, err := protectedCoreLocalEndpoint(invalid); err == nil || endpoint != (egress.LocalEndpoint{}) {
			t.Fatalf("invalid endpoint accepted: endpoint=%+v err=%v", endpoint, err)
		}
	}
}

func TestProtectedEgressValidationFailsClosed(t *testing.T) {
	if err := validateProtectedEgress([]egress.Assessment{{Status: egress.StatusLocal}, {Status: egress.StatusContentProtected}, {Status: egress.StatusBlocked}}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []egress.Status{egress.StatusObserved, "future_status"} {
		err := validateProtectedEgress([]egress.Assessment{{Status: status}})
		var veilErr *domain.VeilError
		if !errors.As(err, &veilErr) || veilErr.Code != domain.ErrUnexpectedEgress {
			t.Fatalf("status=%q err=%v", status, err)
		}
	}
}
