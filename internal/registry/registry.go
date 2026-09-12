package registry

import (
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

type CallNode struct{ SessionID, ParentSessionID, AgentID, SurfaceID string }

func CallTree(nodes []CallNode) (map[string][]CallNode, error) {
	known := map[string]struct{}{}
	result := map[string][]CallNode{}
	for _, node := range nodes {
		if node.SessionID == "" || node.AgentID == "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "session and agent ids are required")
		}
		if _, ok := known[node.SessionID]; ok {
			return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "duplicate session id")
		}
		known[node.SessionID] = struct{}{}
	}
	for _, node := range nodes {
		if node.ParentSessionID != "" {
			if _, ok := known[node.ParentSessionID]; !ok {
				return nil, domain.NewError(domain.ErrInvalidContract, "build call tree", "parent session is unknown")
			}
		}
		result[node.ParentSessionID] = append(result[node.ParentSessionID], node)
	}
	return result, nil
}
