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
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
)

type Document struct {
	SchemaVersion string        `json:"schema_version"`
	Default       domain.Action `json:"default"`
	Rules         []Rule        `json:"rules"`
}

func (d Document) Engine() (Engine, error) {
	if d.SchemaVersion != "v1" || !d.Default.Valid() {
		return Engine{}, domain.NewError(domain.ErrInvalidContract, "load policy", "unsupported schema or default action")
	}
	for _, rule := range d.Rules {
		if !rule.Action.Valid() {
			return Engine{}, domain.NewError(domain.ErrInvalidContract, "load policy", "invalid rule action")
		}
	}
	return Engine{Default: d.Default, Rules: append([]Rule(nil), d.Rules...)}, nil
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, domain.NewError(domain.ErrInvalidContract, "create policy store", "path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
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
	s.mu.Lock()
	defer s.mu.Unlock()
	temp := s.path + ".tmp"
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
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
	return os.Rename(temp, s.path)
}
func (s *Store) Load() (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := os.ReadFile(s.path)
	if err != nil {
		return Document{}, err
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

type approvalResult struct{ action domain.Action }
type Broker struct {
	mu      sync.Mutex
	pending map[string]chan approvalResult
}

func NewBroker() *Broker { return &Broker{pending: map[string]chan approvalResult{}} }
func (b *Broker) Request(ctx context.Context, _ domain.Finding) (domain.Action, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return domain.ActionBlock, err
	}
	id := hex.EncodeToString(idBytes)
	channel := make(chan approvalResult, 1)
	b.mu.Lock()
	b.pending[id] = channel
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.pending, id); b.mu.Unlock() }()
	select {
	case result := <-channel:
		return result.action, nil
	case <-ctx.Done():
		return domain.ActionBlock, domain.NewError(domain.ErrInteractionRequired, "resolve ASK", "approval timed out")
	}
}
func (b *Broker) Pending() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ids := make([]string, 0, len(b.pending))
	for id := range b.pending {
		ids = append(ids, id)
	}
	return ids
}
func (b *Broker) Resolve(id string, action domain.Action) bool {
	if action != domain.ActionAllow && action != domain.ActionRedact && action != domain.ActionBlock {
		return false
	}
	b.mu.Lock()
	channel, ok := b.pending[id]
	if ok {
		delete(b.pending, id)
	}
	b.mu.Unlock()
	if !ok {
		return false
	}
	channel <- approvalResult{action: action}
	return true
}
