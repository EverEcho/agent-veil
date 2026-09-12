package egress

import (
	"sort"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
)

const DefaultMaxProcessSnapshot = 4096

type ProcessIdentity struct {
	ProcessID int    `json:"process_id"`
	StartedAt uint64 `json:"started_at"`
}

type Process struct {
	ProcessIdentity
	ParentID int `json:"parent_id"`
}

type ProcessTree struct {
	mu           sync.RWMutex
	root         ProcessIdentity
	maxProcesses int
	descendants  map[ProcessIdentity]Process
}

func NewProcessTree(root ProcessIdentity, maxProcesses int) (*ProcessTree, error) {
	if !validProcessIdentity(root) || maxProcesses < 1 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create process tree", "root identity and process limit are required")
	}
	return &ProcessTree{root: root, maxProcesses: maxProcesses, descendants: map[ProcessIdentity]Process{}}, nil
}

func (t *ProcessTree) Update(snapshot []Process) error {
	if len(snapshot) == 0 || len(snapshot) > t.maxProcesses {
		return domain.NewError(domain.ErrInvalidContract, "update process tree", "process snapshot is empty or exceeds its limit")
	}
	byPID := make(map[int]Process, len(snapshot))
	for _, process := range snapshot {
		if !validProcessIdentity(process.ProcessIdentity) || process.ParentID < 0 || process.ParentID == process.ProcessID {
			return domain.NewError(domain.ErrInvalidContract, "update process tree", "process identity or parent is invalid")
		}
		if _, duplicate := byPID[process.ProcessID]; duplicate {
			return domain.NewError(domain.ErrInvalidContract, "update process tree", "process snapshot contains a duplicate PID")
		}
		byPID[process.ProcessID] = process
	}
	root, ok := byPID[t.root.ProcessID]
	if !ok || root.StartedAt != t.root.StartedAt {
		return domain.NewError(domain.ErrInvalidContract, "update process tree", "root process exited or its PID was reused")
	}
	state := make(map[int]uint8, len(snapshot))
	descends := make(map[int]bool, len(snapshot))
	var visit func(int) (bool, error)
	visit = func(pid int) (bool, error) {
		if state[pid] == 1 {
			return false, domain.NewError(domain.ErrInvalidContract, "update process tree", "process snapshot contains a parent cycle")
		}
		if state[pid] == 2 {
			return descends[pid], nil
		}
		process, ok := byPID[pid]
		if !ok {
			return false, nil
		}
		state[pid] = 1
		isDescendant := process.ProcessIdentity == t.root
		if !isDescendant && process.ParentID != 0 {
			parentDescends, err := visit(process.ParentID)
			if err != nil {
				return false, err
			}
			isDescendant = parentDescends
		}
		state[pid] = 2
		descends[pid] = isDescendant
		return isDescendant, nil
	}
	for pid := range byPID {
		if _, err := visit(pid); err != nil {
			return err
		}
	}
	result := make(map[ProcessIdentity]Process)
	for pid, process := range byPID {
		if descends[pid] {
			result[process.ProcessIdentity] = process
		}
	}
	t.mu.Lock()
	t.descendants = result
	t.mu.Unlock()
	return nil
}

func (t *ProcessTree) Contains(identity ProcessIdentity) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.descendants[identity]
	return ok
}

func (t *ProcessTree) Descendants() []Process {
	t.mu.RLock()
	result := make([]Process, 0, len(t.descendants))
	for _, process := range t.descendants {
		result = append(result, process)
	}
	t.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].ProcessID != result[j].ProcessID {
			return result[i].ProcessID < result[j].ProcessID
		}
		return result[i].StartedAt < result[j].StartedAt
	})
	return result
}

func validProcessIdentity(identity ProcessIdentity) bool {
	return identity.ProcessID > 0 && identity.StartedAt > 0
}
