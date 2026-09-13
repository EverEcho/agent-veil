package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/redactor"
)

const (
	DefaultMaxLegacySSEChannels        = 256
	DefaultMaxLegacySSEPostsPerChannel = 8
	MaximumLegacySSEChannels           = 1024
	MaximumLegacySSEPostsPerChannel    = 64
	maxLegacySSEUpstreamBytes          = 4096
)

type LegacySSELimits struct {
	MaxChannels        int
	MaxPostsPerChannel int
}

type LegacySSEBinding struct {
	ID        string
	SessionID string
	RouteID   string
	Upstream  *url.URL
	ExpiresAt time.Time
	Context   context.Context
	Vault     *redactor.Vault
}

type legacySSEChannel struct {
	binding LegacySSEBinding
	cancel  context.CancelFunc
	posts   chan struct{}
}

// LegacySSEManager owns the state that joins a legacy MCP GET event stream to
// its dynamically advertised POST endpoint. It is intentionally independent
// of Handler because Core constructs a fresh proxy Handler for each request.
type LegacySSEManager struct {
	mu       sync.Mutex
	channels map[string]*legacySSEChannel
	limits   LegacySSELimits
	now      func() time.Time
	random   io.Reader
}

func NewLegacySSEManager(limits LegacySSELimits) (*LegacySSEManager, error) {
	if limits.MaxChannels < 1 || limits.MaxChannels > MaximumLegacySSEChannels || limits.MaxPostsPerChannel < 1 || limits.MaxPostsPerChannel > MaximumLegacySSEPostsPerChannel {
		return nil, domain.NewError(domain.ErrInvalidContract, "create legacy SSE manager", "channel and POST concurrency limits must be within configured bounds")
	}
	return &LegacySSEManager{channels: make(map[string]*legacySSEChannel), limits: limits, now: time.Now, random: rand.Reader}, nil
}

func NewDefaultLegacySSEManager() *LegacySSEManager {
	manager, _ := NewLegacySSEManager(LegacySSELimits{MaxChannels: DefaultMaxLegacySSEChannels, MaxPostsPerChannel: DefaultMaxLegacySSEPostsPerChannel})
	return manager
}

// Open transfers ownership of vault to the manager on success. The caller
// retains ownership on error.
func (m *LegacySSEManager) Open(sessionID, routeID string, upstream *url.URL, expiresAt time.Time, sessionContext context.Context, vault *redactor.Vault) (LegacySSEBinding, error) {
	if m == nil || !routeIDPattern.MatchString(sessionID) || !routeIDPattern.MatchString(routeID) || !validLegacySSEUpstream(upstream) || expiresAt.IsZero() || sessionContext == nil || vault == nil {
		return LegacySSEBinding{}, domain.NewError(domain.ErrInvalidContract, "open legacy SSE channel", "channel binding is incomplete")
	}
	select {
	case <-sessionContext.Done():
		return LegacySSEBinding{}, domain.NewError(domain.ErrUnauthorizedRoute, "open legacy SSE channel", "session is already revoked")
	default:
	}
	now := m.now()
	if !expiresAt.After(now) {
		return LegacySSEBinding{}, domain.NewError(domain.ErrUnauthorizedRoute, "open legacy SSE channel", "session is expired")
	}
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(m.random, idBytes); err != nil {
		return LegacySSEBinding{}, domain.NewError(domain.ErrInvalidContract, "open legacy SSE channel", "secure randomness is unavailable")
	}
	id := "legacy-" + hex.EncodeToString(idBytes)
	channelContext, cancel := context.WithDeadline(sessionContext, expiresAt)
	binding := LegacySSEBinding{ID: id, SessionID: sessionID, RouteID: routeID, Upstream: cloneURL(upstream), ExpiresAt: expiresAt, Context: channelContext, Vault: vault}
	channel := &legacySSEChannel{binding: binding, cancel: cancel, posts: make(chan struct{}, m.limits.MaxPostsPerChannel)}
	m.mu.Lock()
	stale := m.pruneLocked(now)
	if len(m.channels) >= m.limits.MaxChannels {
		m.mu.Unlock()
		cancel()
		destroyLegacyChannels(stale)
		return LegacySSEBinding{}, domain.NewError(domain.ErrInvalidContract, "open legacy SSE channel", "legacy SSE channel capacity is exhausted")
	}
	if _, collision := m.channels[id]; collision {
		m.mu.Unlock()
		cancel()
		destroyLegacyChannels(stale)
		return LegacySSEBinding{}, domain.NewError(domain.ErrInvalidContract, "open legacy SSE channel", "legacy SSE channel identity collision")
	}
	m.channels[id] = channel
	m.mu.Unlock()
	destroyLegacyChannels(stale)
	return cloneLegacyBinding(binding), nil
}

func validLegacySSEUpstream(upstream *url.URL) bool {
	if upstream == nil || len(upstream.String()) == 0 || len(upstream.String()) > maxLegacySSEUpstreamBytes || upstream.User != nil || upstream.Host == "" || upstream.Fragment != "" || upstream.Opaque != "" || upstream.RawPath != "" || upstream.ForceQuery {
		return false
	}
	return upstream.Scheme == "http" || upstream.Scheme == "https"
}

// Acquire reserves one bounded POST slot and requires the complete capability
// tuple. The returned release function must be called exactly once.
func (m *LegacySSEManager) Acquire(ctx context.Context, id, sessionID, routeID string) (LegacySSEBinding, func(), bool) {
	if m == nil || ctx == nil {
		return LegacySSEBinding{}, nil, false
	}
	now := m.now()
	m.mu.Lock()
	stale := m.pruneLocked(now)
	channel, ok := m.channels[id]
	if !ok || channel.binding.SessionID != sessionID || channel.binding.RouteID != routeID {
		m.mu.Unlock()
		destroyLegacyChannels(stale)
		return LegacySSEBinding{}, nil, false
	}
	m.mu.Unlock()
	destroyLegacyChannels(stale)
	select {
	case channel.posts <- struct{}{}:
	case <-ctx.Done():
		return LegacySSEBinding{}, nil, false
	case <-channel.binding.Context.Done():
		return LegacySSEBinding{}, nil, false
	}
	m.mu.Lock()
	current := m.channels[id]
	stillActive := current == channel && channel.binding.ExpiresAt.After(m.now())
	m.mu.Unlock()
	if !stillActive {
		<-channel.posts
		return LegacySSEBinding{}, nil, false
	}
	var once sync.Once
	release := func() { once.Do(func() { <-channel.posts }) }
	return cloneLegacyBinding(channel.binding), release, true
}

func (m *LegacySSEManager) Close(id, sessionID, routeID string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	channel, ok := m.channels[id]
	if ok && channel.binding.SessionID == sessionID && channel.binding.RouteID == routeID {
		delete(m.channels, id)
	} else {
		ok = false
	}
	m.mu.Unlock()
	if ok {
		destroyLegacyChannels([]*legacySSEChannel{channel})
	}
	return ok
}

func (m *LegacySSEManager) CloseAll() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	channels := make([]*legacySSEChannel, 0, len(m.channels))
	for id, channel := range m.channels {
		channels = append(channels, channel)
		delete(m.channels, id)
	}
	m.mu.Unlock()
	destroyLegacyChannels(channels)
	return len(channels)
}

func (m *LegacySSEManager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	stale := m.pruneLocked(m.now())
	length := len(m.channels)
	m.mu.Unlock()
	destroyLegacyChannels(stale)
	return length
}

func (m *LegacySSEManager) pruneLocked(now time.Time) []*legacySSEChannel {
	var stale []*legacySSEChannel
	for id, channel := range m.channels {
		if channel.binding.ExpiresAt.After(now) {
			select {
			case <-channel.binding.Context.Done():
			default:
				continue
			}
		}
		delete(m.channels, id)
		stale = append(stale, channel)
	}
	return stale
}

func destroyLegacyChannels(channels []*legacySSEChannel) {
	for _, channel := range channels {
		channel.cancel()
		channel.binding.Vault.Destroy()
	}
}

func cloneLegacyBinding(binding LegacySSEBinding) LegacySSEBinding {
	binding.Upstream = cloneURL(binding.Upstream)
	return binding
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}
