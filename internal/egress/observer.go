package egress

import (
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
)

type ProcessSnapshotter interface {
	Snapshot() ([]Process, error)
}

type ConnectionSnapshotter interface {
	Connections([]Process) ([]Connection, error)
}

// Observer performs one serialized, fail-closed observation cycle. It never
// returns assessments derived from a partial process or connection snapshot.
type Observer struct {
	mu          sync.Mutex
	tree        *ProcessTree
	processes   ProcessSnapshotter
	connections ConnectionSnapshotter
}

func NewObserver(root ProcessIdentity, maxProcesses int, processes ProcessSnapshotter, connections ConnectionSnapshotter) (*Observer, error) {
	if processes == nil || connections == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "create egress observer", "process and connection collectors are required")
	}
	tree, err := NewProcessTree(root, maxProcesses)
	if err != nil {
		return nil, err
	}
	return &Observer{tree: tree, processes: processes, connections: connections}, nil
}

func (o *Observer) Observe(expected []Expected) ([]Assessment, error) {
	return o.ObserveWithLocalEndpoints(expected, nil)
}

func (o *Observer) ObserveWithLocalEndpoints(expected []Expected, localEndpoints []LocalEndpoint) ([]Assessment, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	snapshot, err := o.processes.Snapshot()
	if err != nil {
		return nil, err
	}
	if err := o.tree.Update(snapshot); err != nil {
		return nil, err
	}
	connections, err := o.connections.Connections(o.tree.Descendants())
	if err != nil {
		return nil, err
	}
	return AssessWithLocalEndpoints(connections, expected, localEndpoints), nil
}
