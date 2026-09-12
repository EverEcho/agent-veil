package registry

import (
	"fmt"
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
	ExpiresAt  time.Time             `json:"expires_at,omitempty"`
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

func (r *Registry) Preview(manifest domain.AgentManifest) (domain.ProtectionPlan, error) {
	return planner.Build(manifest, r.capabilities)
}

// Reconcile atomically replaces a registration only after its manifest and plan
// validate. A failed change marks the agent blocked instead of retaining a stale
// "protected" claim.
func (r *Registry) Reconcile(manifest domain.AgentManifest) (Entry, error) {
	return r.reconcile(manifest, 0)
}

func (r *Registry) ReconcileLeased(manifest domain.AgentManifest, ttl time.Duration) (Entry, error) {
	if ttl <= 0 {
		return Entry{}, domain.NewError(domain.ErrInvalidContract, "reconcile leased integration", "positive lease ttl is required")
	}
	return r.reconcile(manifest, ttl)
}

func (r *Registry) reconcile(manifest domain.AgentManifest, ttl time.Duration) (Entry, error) {
	plan, err := planner.Build(manifest, r.capabilities)
	if err != nil && manifest.Agent.ID == "" {
		return Entry{Manifest: manifest, State: StateBlocked, UpdatedAt: r.now(), ErrorCode: domain.ErrInvalidContract}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	previous := r.entries[manifest.Agent.ID]
	generation := previous.Generation + 1
	bindPlanGeneration(&plan, generation)
	if err != nil {
		blocked := Entry{Manifest: manifest, State: StateBlocked, Generation: generation, UpdatedAt: now, ErrorCode: domain.ErrInvalidContract}
		r.entries[manifest.Agent.ID] = cloneEntry(blocked)
		return cloneEntry(blocked), err
	}
	for _, coverage := range plan.Coverage {
		if required(manifest, coverage.SurfaceID) && coverage.Status != domain.CoverageProtected && coverage.Status != domain.CoverageLocal {
			blocked := Entry{Manifest: manifest, Plan: plan, State: StateBlocked, Generation: generation, UpdatedAt: now, ErrorCode: domain.ErrPolicyBlocked}
			r.entries[manifest.Agent.ID] = cloneEntry(blocked)
			return cloneEntry(blocked), domain.NewError(domain.ErrPolicyBlocked, "reconcile integration", "required surface is not fully protected or local")
		}
	}
	entry := Entry{Manifest: manifest, Plan: plan, State: StateActive, Generation: generation, UpdatedAt: now}
	if ttl > 0 {
		entry.ExpiresAt = now.Add(ttl)
	}
	r.entries[manifest.Agent.ID] = cloneEntry(entry)
	return cloneEntry(entry), nil
}

func bindPlanGeneration(plan *domain.ProtectionPlan, generation uint64) {
	suffix := fmt.Sprintf("-g%d", generation)
	for index := range plan.Routes {
		plan.Routes[index].ID += suffix
	}
	for index := range plan.Coverage {
		if plan.Coverage[index].RouteID != "" {
			plan.Coverage[index].RouteID += suffix
		}
	}
}

func (r *Registry) Get(agentID string) (Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(r.now())
	entry, ok := r.entries[agentID]
	return cloneEntry(entry), ok
}
func (r *Registry) List() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(r.now())
	values := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		values = append(values, cloneEntry(entry))
	}
	return values
}

func (r *Registry) Heartbeat(agentID string, generation uint64, ttl time.Duration) (Entry, error) {
	if agentID == "" || generation == 0 || ttl <= 0 {
		return Entry{}, domain.NewError(domain.ErrInvalidContract, "renew integration lease", "agent id, generation and positive ttl are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	entry, ok := r.entries[agentID]
	if !ok || entry.State != StateActive || entry.ExpiresAt.IsZero() || entry.Generation != generation {
		return cloneEntry(entry), domain.NewError(domain.ErrUnauthorizedRoute, "renew integration lease", "active lease generation was not found")
	}
	entry.ExpiresAt = now.Add(ttl)
	entry.UpdatedAt = now
	r.entries[agentID] = entry
	return cloneEntry(entry), nil
}
func (r *Registry) Remove(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, agentID)
}

func (r *Registry) RemoveGeneration(agentID string, generation uint64) bool {
	if agentID == "" || generation == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[agentID]
	if !ok || entry.Generation != generation {
		return false
	}
	delete(r.entries, agentID)
	return true
}

// Block invalidates any prior active protection claim while retaining the last
// known manifest for diagnostics.
func (r *Registry) Block(agentID string, code domain.ErrorCode) (Entry, error) {
	if agentID == "" || code == "" {
		return Entry{}, domain.NewError(domain.ErrInvalidContract, "block integration", "agent id and error code are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.entries[agentID]
	manifest := previous.Manifest
	if manifest.Agent.ID == "" {
		manifest = domain.AgentManifest{SchemaVersion: "v1", Agent: domain.AgentInstance{ID: agentID, Kind: "managed", Mode: domain.ModeManaged}}
	}
	entry := Entry{Manifest: manifest, State: StateBlocked, Generation: previous.Generation + 1, UpdatedAt: r.now(), ErrorCode: code}
	r.entries[agentID] = cloneEntry(entry)
	return cloneEntry(entry), domain.NewError(code, "monitor integration", "managed integration snapshot is unavailable or invalid")
}

func cloneEntry(source Entry) Entry {
	result := source
	result.Manifest = cloneManifest(source.Manifest)
	result.Plan.Routes = append([]domain.ProtectedRoute(nil), source.Plan.Routes...)
	result.Plan.Coverage = append([]domain.SurfaceCoverage(nil), source.Plan.Coverage...)
	result.Plan.Risks = append([]domain.ProtectionRisk(nil), source.Plan.Risks...)
	return result
}

func cloneManifest(source domain.AgentManifest) domain.AgentManifest {
	result := source
	result.Agent.Metadata = cloneStrings(source.Agent.Metadata)
	result.Surfaces = make([]domain.EgressSurface, len(source.Surfaces))
	for index, surface := range source.Surfaces {
		result.Surfaces[index] = surface
		result.Surfaces[index].Metadata = cloneStrings(surface.Metadata)
		if surface.Upstream != nil {
			upstream := *surface.Upstream
			result.Surfaces[index].Upstream = &upstream
		}
	}
	return result
}

func cloneStrings(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (r *Registry) expireLocked(now time.Time) {
	for agentID, entry := range r.entries {
		if entry.State != StateActive || entry.ExpiresAt.IsZero() || entry.ExpiresAt.After(now) {
			continue
		}
		entry.State = StateBlocked
		entry.Plan = domain.ProtectionPlan{}
		entry.Generation++
		entry.UpdatedAt = now
		entry.ExpiresAt = time.Time{}
		entry.ErrorCode = domain.ErrIntegrationExpired
		r.entries[agentID] = entry
	}
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
