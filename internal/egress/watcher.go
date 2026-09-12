package egress

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

const (
	MinWatchInterval = 10 * time.Millisecond
	MaxWatchInterval = time.Minute
)

type ObservationSource interface {
	ObserveWithLocalEndpoints([]Expected, []LocalEndpoint) ([]Assessment, error)
}

type AssessmentHandler func(context.Context, []Assessment) error

// Watcher runs complete observation cycles serially. Collection and handler
// failures stop the watcher so callers can fail closed instead of continuing
// with a stale or partially processed snapshot.
type Watcher struct {
	mu             sync.Mutex
	running        bool
	source         ObservationSource
	interval       time.Duration
	expected       []Expected
	localEndpoints []LocalEndpoint
	handle         AssessmentHandler
}

func NewWatcher(source ObservationSource, interval time.Duration, expected []Expected, localEndpoints []LocalEndpoint, handle AssessmentHandler) (*Watcher, error) {
	if source == nil || handle == nil || interval < MinWatchInterval || interval > MaxWatchInterval {
		return nil, domain.NewError(domain.ErrInvalidContract, "create egress watcher", "source, handler, and bounded interval are required")
	}
	return &Watcher{
		source:         source,
		interval:       interval,
		expected:       append([]Expected(nil), expected...),
		localEndpoints: append([]LocalEndpoint(nil), localEndpoints...),
		handle:         handle,
	}, nil
}

func (w *Watcher) Run(ctx context.Context) error {
	if ctx == nil {
		return domain.NewError(domain.ErrInvalidContract, "run egress watcher", "context is required")
	}
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return domain.NewError(domain.ErrInvalidContract, "run egress watcher", "watcher is already running")
	}
	w.running = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		assessments, err := w.source.ObserveWithLocalEndpoints(w.expected, w.localEndpoints)
		if err != nil {
			return fmt.Errorf("observe process egress: %w", err)
		}
		if err := w.handle(ctx, assessments); err != nil {
			return fmt.Errorf("handle process egress assessment: %w", err)
		}
		timer := time.NewTimer(w.interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}
