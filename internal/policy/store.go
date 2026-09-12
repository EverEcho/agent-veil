package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

type Document struct {
	SchemaVersion string        `json:"schema_version"`
	Default       domain.Action `json:"default"`
	Rules         []Rule        `json:"rules"`
}

func DefaultDocument() Document {
	return Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: []Rule{{Scope: Scope{FindingType: "secret.private_key"}, Action: domain.ActionBlock}}}
}

func (d Document) Engine() (Engine, error) {
	if d.SchemaVersion != "v1" || !d.Default.Valid() {
		return Engine{}, domain.NewError(domain.ErrInvalidContract, "load policy", "unsupported schema or default action")
	}
	if err := validateRules(d.Rules); err != nil {
		return Engine{}, domain.NewError(domain.ErrInvalidContract, "load policy", "invalid or ambiguous rules")
	}
	return Engine{Default: d.Default, Rules: append([]Rule(nil), d.Rules...)}, nil
}

type Store struct {
	path string
	mu   sync.Mutex
}

const maxPolicyBytes = 1 << 20

func NewStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, domain.NewError(domain.ErrInvalidContract, "create policy store", "path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create policy store", "policy directory permissions or type are unsafe")
	}
	return &Store{path: path}, nil
}
func (s *Store) Save(document Document) error {
	if _, err := document.Engine(); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > maxPolicyBytes {
		return domain.NewError(domain.ErrInvalidContract, "save policy", "policy file exceeds its size limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.CreateTemp(filepath.Dir(s.path), ".policy-*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(payload); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, s.path); err != nil {
		return err
	}
	return syncPolicyDirectory(filepath.Dir(s.path))
}
func (s *Store) Load() (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Lstat(s.path)
	if err != nil {
		return Document{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return Document{}, domain.NewError(domain.ErrInvalidContract, "load policy", "policy file permissions or type are unsafe")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return Document{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Document{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return Document{}, domain.NewError(domain.ErrInvalidContract, "load policy", "policy file changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil {
		return Document{}, err
	}
	if len(payload) > maxPolicyBytes {
		return Document{}, domain.NewError(domain.ErrInvalidContract, "load policy", "policy file is too large")
	}
	if err := jsonsafe.Validate(payload); err != nil {
		return Document{}, domain.NewError(domain.ErrInvalidContract, "load policy", "policy JSON is invalid or ambiguous")
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, domain.NewError(domain.ErrInvalidContract, "load policy", "policy JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Document{}, domain.NewError(domain.ErrInvalidContract, "load policy", "policy JSON contains trailing data")
	}
	if _, err := document.Engine(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func syncPolicyDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type Approval struct {
	ID      string         `json:"id"`
	Finding domain.Finding `json:"finding"`
}
type approvalResult struct{ action domain.Action }
type pendingApproval struct {
	finding domain.Finding
	channel chan approvalResult
}
type Broker struct {
	mu      sync.Mutex
	pending map[string]pendingApproval
}

const maxPendingApprovals = 1024

func NewBroker() *Broker { return &Broker{pending: map[string]pendingApproval{}} }
func (b *Broker) Request(ctx context.Context, finding domain.Finding) (domain.Action, error) {
	if ctx == nil || finding.Validate(finding.Location.End) != nil {
		return domain.ActionBlock, domain.NewError(domain.ErrInvalidContract, "request ASK", "context or finding is invalid")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return domain.ActionBlock, err
	}
	id := hex.EncodeToString(idBytes)
	channel := make(chan approvalResult, 1)
	b.mu.Lock()
	if len(b.pending) >= maxPendingApprovals {
		b.mu.Unlock()
		return domain.ActionBlock, domain.NewError(domain.ErrInteractionRequired, "request ASK", "pending approval capacity is exhausted")
	}
	b.pending[id] = pendingApproval{finding: finding, channel: channel}
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.pending, id); b.mu.Unlock() }()
	select {
	case result := <-channel:
		return result.action, nil
	case <-ctx.Done():
		return domain.ActionBlock, domain.NewError(domain.ErrInteractionRequired, "resolve ASK", "approval timed out")
	}
}
func (b *Broker) Pending() []Approval {
	b.mu.Lock()
	defer b.mu.Unlock()
	approvals := make([]Approval, 0, len(b.pending))
	for id, pending := range b.pending {
		approvals = append(approvals, Approval{ID: id, Finding: pending.finding})
	}
	sort.Slice(approvals, func(i, j int) bool { return approvals[i].ID < approvals[j].ID })
	return approvals
}
func (b *Broker) Resolve(id string, action domain.Action) bool {
	if action != domain.ActionAllow && action != domain.ActionRedact && action != domain.ActionBlock {
		return false
	}
	b.mu.Lock()
	pending, ok := b.pending[id]
	if ok {
		delete(b.pending, id)
	}
	b.mu.Unlock()
	if !ok {
		return false
	}
	pending.channel <- approvalResult{action: action}
	return true
}
