package attach

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
	native "github.com/agentveil/agentveil/sdk/native"
)

const managementToken = "01234567890123456789012345678901"

type recordingTarget struct {
	mu       sync.Mutex
	bindings []Binding
	restored chan struct{}
}

func (t *recordingTarget) Apply(_ context.Context, binding Binding) error {
	t.mu.Lock()
	t.bindings = append(t.bindings, binding)
	t.mu.Unlock()
	return nil
}

func (t *recordingTarget) Restore(context.Context) error {
	close(t.restored)
	return nil
}

func TestControllerAttachesRotatesAndRestores(t *testing.T) {
	reg := registry.New(planner.Options{DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}, Capabilities: map[domain.Protocol]planner.Capability{
		domain.ProtocolOpenAIChat: {RequestInspection: true, ResponseInspection: true, StreamInspection: true},
	}})
	manager := session.NewManager()
	server, err := core.New(manager, managementToken)
	if err != nil {
		t.Fatal(err)
	}
	server.WithRegistry(reg)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	controller, err := New(server.Endpoint(), managementToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := native.AgentManifest{SchemaVersion: "v1", Agent: native.AgentInstance{ID: "attach-test", Kind: "dynamic-agent", Version: "1", Mode: native.ModeAttach}, Surfaces: []native.EgressSurface{{
		ID: "primary", Name: "Primary", Type: native.SurfaceModelPrimary, Protocol: native.ProtocolOpenAIChat,
		Upstream: &native.Upstream{Scheme: "https", Host: "api.example", Port: 443}, Auth: native.AuthStrategy{Type: native.AuthPassthrough}, ConfigSource: "native:dynamic", Rewritable: true, Required: true,
	}}}
	target := &recordingTarget{restored: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- controller.Run(ctx, manifest, target, Options{LeaseTTL: 2 * time.Second, HeartbeatInterval: 100 * time.Millisecond, SessionTTL: 2 * time.Second})
	}()
	deadline := time.After(3 * time.Second)
	for {
		target.mu.Lock()
		count := len(target.bindings)
		var first, second Binding
		if count >= 2 {
			first, second = target.bindings[0], target.bindings[1]
		}
		target.mu.Unlock()
		if count >= 2 {
			if first.SessionID == second.SessionID || len(first.Routes) != 1 || first.Routes[0].Headers["X-Veil-Route-Token"] == second.Routes[0].Headers["X-Veil-Route-Token"] || first.Routes[0].CapabilityValue == "" || first.Routes[0].BaseURL != first.Routes[0].RouteURL+"/v1" {
				t.Fatalf("Attach capability did not rotate safely: first=%+v second=%+v", first, second)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("Attach session was not rotated")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case <-target.restored:
	default:
		t.Fatal("attached target was not restored")
	}
	if len(manager.List()) != 0 || len(reg.List()) != 0 {
		t.Fatal("Attach cleanup left active authority")
	}
}
