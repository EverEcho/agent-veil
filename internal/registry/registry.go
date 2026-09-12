package registry

import (
	"sort"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/planner"
)

type State string

const (
	StateActive  State = "active"
	StateBlocked State = "blocked"
)

type Entry struct {
	Manifest   domain.AgentManifest  `json:"manifest"`
	Plan       domain.ProtectionPlan `json:"plan"`
	State      State                 `json:"state"`
	Generation uint64                `json:"generation"`
	UpdatedAt  time.Time             `json:"updated_at"`
	ErrorCode  domain.ErrorCode      `json:"error_code,omitempty"`
}
type Registry struct {
	mu           sync.RWMutex
	entries      map[string]Entry
	capabilities planner.Options
	now          func() time.Time
}

func New(options planner.Options) *Registry {
	return &Registry{entries: map[string]Entry{}, capabilities: options, now: time.Now}
}

// Reconcile atomically replaces a registration only after its manifest and plan
// validate. A failed change marks the agent blocked instead of retaining a stale
// "protected" claim.
func (r *Registry) Reconcile(manifest domain.AgentManifest) (Entry, error) {
	plan, err := planner.Build(manifest, r.capabilities)
	if err != nil && manifest.Agent.ID == "" {
		return Entry{Manifest: manifest, State: StateBlocked, UpdatedAt: r.now(), ErrorCode: domain.ErrInvalidContract}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.entries[manifest.Agent.ID]
	generation := previous.Generation + 1
	if err != nil {
		blocked := Entry{Manifest: manifest, State: StateBlocked, Generation: generation, UpdatedAt: r.now(), ErrorCode: domain.ErrInvalidContract}
		r.entries[manifest.Agent.ID] = blocked
		return blocked, err
	}
	for _, coverage := range plan.Coverage {
		if coverage.Status == domain.CoverageUnprotected && required(manifest, coverage.SurfaceID) {
			blocked := Entry{Manifest: manifest, Plan: plan, State: StateBlocked, Generation: generation, UpdatedAt: r.now(), ErrorCode: domain.ErrPolicyBlocked}
			r.entries[manifest.Agent.ID] = blocked
			return blocked, domain.NewError(domain.ErrPolicyBlocked, "reconcile integration", "required surface is unprotected")
		}
	}
	entry := Entry{Manifest: manifest, Plan: plan, State: StateActive, Generation: generation, UpdatedAt: r.now()}
	r.entries[manifest.Agent.ID] = entry
	return entry, nil
}

func (r *Registry) Get(agentID string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[agentID]
	return entry, ok
}
func (r *Registry) List() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	values := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		values = append(values, entry)
	}
	return values
}
func (r *Registry) Remove(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, agentID)
}
func required(manifest domain.AgentManifest, id string) bool {
	for _, surface := range manifest.Surfaces {
		if surface.ID == id {
			return surface.Required
		}
	}
	return false
}

type CallSurface struct {
	RouteID   string                `json:"route_id"`
	AgentID   string                `json:"agent_id,omitempty"`
	SurfaceID string                `json:"surface_id,omitempty"`
	Coverage  domain.CoverageStatus `json:"coverage"`
}

type CallNode struct {
	SessionID       string        `json:"session_id"`
	ParentSessionID string        `json:"parent_session_id,omitempty"`
	Surfaces        []CallSurface `json:"surfaces"`
}

func CallTree(nodes []CallNode) (map[string][]CallNode, error) {
	known := map[string]struct{}{}
	parents := map[string]string{}
	result := map[string][]CallNode{}
	for _, node := range nodes {
		if node.SessionID == "" || len(node.Surfaces) == 0 {
			return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "session and surfaces are required")
		}
		for _, surface := range node.Surfaces {
			if surface.RouteID == "" || !surface.Coverage.Valid() {
				return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "call surface is invalid")
			}
		}
		if _, ok := known[node.SessionID]; ok {
			return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "duplicate session id")
		}
		known[node.SessionID] = struct{}{}
		parents[node.SessionID] = node.ParentSessionID
	}
	for _, node := range nodes {
		if node.ParentSessionID != "" {
			if _, ok := known[node.ParentSessionID]; !ok {
				return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "parent session is unknown")
			}
		}
		result[node.ParentSessionID] = append(result[node.ParentSessionID], node)
	}
	state := map[string]uint8{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return domain.NewError(domain.ErrInvalidContract, "build call tree", "session ancestry contains a cycle")
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		if parent := parents[id]; parent != "" {
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range known {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	for parentID := range result {
		sort.Slice(result[parentID], func(i, j int) bool { return result[parentID][i].SessionID < result[parentID][j].SessionID })
	}
	return result, nil
}
