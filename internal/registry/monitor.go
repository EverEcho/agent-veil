package registry

import (
	"context"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type SnapshotSource interface {
	Snapshot(context.Context) (revision string, manifest domain.AgentManifest, err error)
}

type Monitor struct {
	registry *Registry
	source   SnapshotSource
	agentID  string
	interval time.Duration

	mu                sync.Mutex
	processedRevision string
}

func NewMonitor(registry *Registry, source SnapshotSource, agentID string, interval time.Duration) (*Monitor, error) {
	if registry == nil || source == nil || agentID == "" || interval <= 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create integration monitor", "registry, source, agent id and positive interval are required")
	}
	return &Monitor{registry: registry, source: source, agentID: agentID, interval: interval}, nil
}

// Check applies at most one revision. A failed snapshot revokes the previous
// active claim; a later valid revision can reconcile and recover it.
func (m *Monitor) Check(ctx context.Context) (Entry, bool, error) {
	revision, manifest, snapshotErr := m.source.Snapshot(ctx)
	invalidRevision := revision == ""
	if revision == "" {
		revision = "\x00invalid-revision"
	}
	m.mu.Lock()
	if revision == m.processedRevision {
		m.mu.Unlock()
		entry, _ := m.registry.Get(m.agentID)
		return entry, false, nil
	}
	m.processedRevision = revision
	m.mu.Unlock()

	if invalidRevision || snapshotErr != nil || manifest.Agent.ID != m.agentID {
		entry, err := m.registry.Block(m.agentID, domain.ErrInvalidContract)
		return entry, true, err
	}
	entry, err := m.registry.Reconcile(manifest)
	return entry, true, err
}

// Run monitors until the context is cancelled. Snapshot failures are reflected
// as Blocked registry state and do not stop recovery attempts.
func (m *Monitor) Run(ctx context.Context) {
	_, _, _ = m.Check(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, _ = m.Check(ctx)
		}
	}
}
