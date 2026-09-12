package egress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingObservationSource struct {
	mu       sync.Mutex
	calls    int
	expected [][]Expected
	local    [][]LocalEndpoint
	result   []Assessment
	err      error
}

func (s *recordingObservationSource) ObserveWithLocalEndpoints(expected []Expected, local []LocalEndpoint) ([]Assessment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.expected = append(s.expected, append([]Expected(nil), expected...))
	s.local = append(s.local, append([]LocalEndpoint(nil), local...))
	return append([]Assessment(nil), s.result...), s.err
}

func TestWatcherObservesImmediatelyAndSerially(t *testing.T) {
	source := &recordingObservationSource{result: []Assessment{{Status: StatusLocal}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handled := 0
	watcher, err := NewWatcher(source, MinWatchInterval, nil, nil, func(_ context.Context, assessments []Assessment) error {
		handled++
		if len(assessments) != 1 || assessments[0].Status != StatusLocal {
			t.Fatalf("assessments=%+v", assessments)
		}
		if handled == 2 {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if handled != 2 || source.calls != 2 {
		t.Fatalf("handled=%d calls=%d", handled, source.calls)
	}
}

func TestWatcherCopiesRouteConfiguration(t *testing.T) {
	expected := []Expected{{ProcessIdentity: identity(1, 10), Transport: TransportTCP, Host: "api.example", Port: 443, RouteID: "route", SurfaceID: "primary"}}
	local := []LocalEndpoint{{Transport: TransportTCP, Host: "127.0.0.1", Port: 48123}}
	source := &recordingObservationSource{}
	ctx, cancel := context.WithCancel(context.Background())
	watcher, err := NewWatcher(source, MinWatchInterval, expected, local, func(context.Context, []Assessment) error {
		cancel()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expected[0].RouteID = "mutated"
	local[0].Port = 1
	if err := watcher.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if source.expected[0][0].RouteID != "route" || source.local[0][0].Port != 48123 {
		t.Fatalf("watcher configuration was mutated: expected=%+v local=%+v", source.expected, source.local)
	}
}

func TestWatcherStopsOnObservationOrHandlerFailure(t *testing.T) {
	failure := errors.New("failed")
	for _, test := range []struct {
		name   string
		source *recordingObservationSource
		handle AssessmentHandler
	}{
		{"observation", &recordingObservationSource{err: failure}, func(context.Context, []Assessment) error { return nil }},
		{"handler", &recordingObservationSource{}, func(context.Context, []Assessment) error { return failure }},
	} {
		t.Run(test.name, func(t *testing.T) {
			watcher, err := NewWatcher(test.source, MinWatchInterval, nil, nil, test.handle)
			if err != nil {
				t.Fatal(err)
			}
			if err := watcher.Run(context.Background()); !errors.Is(err, failure) || test.source.calls != 1 {
				t.Fatalf("calls=%d err=%v", test.source.calls, err)
			}
		})
	}
}

func TestWatcherRejectsInvalidConfiguration(t *testing.T) {
	source := &recordingObservationSource{}
	handle := func(context.Context, []Assessment) error { return nil }
	for _, create := range []func() (*Watcher, error){
		func() (*Watcher, error) { return NewWatcher(nil, MinWatchInterval, nil, nil, handle) },
		func() (*Watcher, error) { return NewWatcher(source, MinWatchInterval, nil, nil, nil) },
		func() (*Watcher, error) {
			return NewWatcher(source, MinWatchInterval-time.Nanosecond, nil, nil, handle)
		},
		func() (*Watcher, error) {
			return NewWatcher(source, MaxWatchInterval+time.Nanosecond, nil, nil, handle)
		},
	} {
		if watcher, err := create(); err == nil || watcher != nil {
			t.Fatalf("invalid watcher accepted: watcher=%+v err=%v", watcher, err)
		}
	}
}

func TestWatcherDoesNotObserveCanceledContext(t *testing.T) {
	source := &recordingObservationSource{}
	watcher, err := NewWatcher(source, MinWatchInterval, nil, nil, func(context.Context, []Assessment) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := watcher.Run(ctx); err != nil || source.calls != 0 {
		t.Fatalf("calls=%d err=%v", source.calls, err)
	}
}
