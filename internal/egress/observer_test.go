package egress

import (
	"errors"
	"testing"
)

type fixedProcessSnapshotter struct {
	snapshot []Process
	err      error
	calls    *int
}

func (f fixedProcessSnapshotter) Snapshot() ([]Process, error) {
	if f.calls != nil {
		*f.calls++
	}
	return f.snapshot, f.err
}

type recordingConnectionSnapshotter struct {
	processes []Process
	result    []Connection
	err       error
	errors    []error
	calls     int
}

func (r *recordingConnectionSnapshotter) Connections(processes []Process) ([]Connection, error) {
	r.calls++
	r.processes = append([]Process(nil), processes...)
	if len(r.errors) >= r.calls {
		return nil, r.errors[r.calls-1]
	}
	return r.result, r.err
}

func TestObserverAssessesOnlyCurrentProcessTree(t *testing.T) {
	root := identity(10, 100)
	collector := &recordingConnectionSnapshotter{result: []Connection{{ProcessIdentity: identity(11, 110), Host: "8.8.8.8", Port: 443}}}
	observer, err := NewObserver(root, 8, fixedProcessSnapshotter{snapshot: []Process{
		{ProcessIdentity: root, ParentID: 1},
		{ProcessIdentity: identity(11, 110), ParentID: 10},
		{ProcessIdentity: identity(20, 200), ParentID: 1},
	}}, collector)
	if err != nil {
		t.Fatal(err)
	}
	assessments, err := observer.Observe(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(collector.processes) != 2 || collector.processes[0].ProcessID != 10 || collector.processes[1].ProcessID != 11 {
		t.Fatalf("collector received processes=%+v", collector.processes)
	}
	if len(assessments) != 1 || assessments[0].Status != StatusObserved || assessments[0].Risk == nil {
		t.Fatalf("assessments=%+v", assessments)
	}
}

func TestObserverNeverReturnsPartialAssessmentOnCollectorFailure(t *testing.T) {
	root := identity(10, 100)
	failure := errors.New("collector failed")
	for _, test := range []struct {
		name      string
		processes ProcessSnapshotter
		sockets   ConnectionSnapshotter
	}{
		{"processes", fixedProcessSnapshotter{err: failure}, &recordingConnectionSnapshotter{}},
		{"connections", fixedProcessSnapshotter{snapshot: []Process{{ProcessIdentity: root, ParentID: 1}}}, &recordingConnectionSnapshotter{result: []Connection{{ProcessIdentity: root, Host: "8.8.8.8", Port: 443}}, err: failure}},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer, err := NewObserver(root, 8, test.processes, test.sockets)
			if err != nil {
				t.Fatal(err)
			}
			assessments, err := observer.Observe(nil)
			if !errors.Is(err, failure) || assessments != nil {
				t.Fatalf("assessments=%+v err=%v", assessments, err)
			}
		})
	}
}

func TestNewObserverRequiresCollectors(t *testing.T) {
	root := identity(10, 100)
	if _, err := NewObserver(root, 8, nil, &recordingConnectionSnapshotter{}); err == nil {
		t.Fatal("nil process collector was accepted")
	}
	if _, err := NewObserver(root, 8, fixedProcessSnapshotter{}, nil); err == nil {
		t.Fatal("nil connection collector was accepted")
	}
}

func TestObserverClassifiesExactLoopbackHopAsLocal(t *testing.T) {
	root := identity(10, 100)
	collector := &recordingConnectionSnapshotter{result: []Connection{{ProcessIdentity: root, Transport: TransportTCP, Host: "127.0.0.1", Port: 48123}}}
	observer, err := NewObserver(root, 8, fixedProcessSnapshotter{snapshot: []Process{{ProcessIdentity: root, ParentID: 1}}}, collector)
	if err != nil {
		t.Fatal(err)
	}
	assessments, err := observer.ObserveWithLocalEndpoints(nil, []LocalEndpoint{{Transport: TransportTCP, Host: "127.0.0.1", Port: 48123}})
	if err != nil {
		t.Fatal(err)
	}
	if len(assessments) != 1 || assessments[0].Status != StatusLocal || assessments[0].Risk != nil {
		t.Fatalf("assessments=%+v", assessments)
	}
}

func TestObserverRetriesOneCompleteCycleAfterProcessChurn(t *testing.T) {
	root := identity(10, 100)
	processCalls := 0
	collector := &recordingConnectionSnapshotter{errors: []error{processSnapshotChanged()}, result: []Connection{{ProcessIdentity: root, Transport: TransportTCP, Host: "127.0.0.1", Port: 48123}}}
	observer, err := NewObserver(root, 8, fixedProcessSnapshotter{snapshot: []Process{{ProcessIdentity: root, ParentID: 1}}, calls: &processCalls}, collector)
	if err != nil {
		t.Fatal(err)
	}
	assessments, err := observer.ObserveWithLocalEndpoints(nil, []LocalEndpoint{{Transport: TransportTCP, Host: "127.0.0.1", Port: 48123}})
	if err != nil || len(assessments) != 1 || assessments[0].Status != StatusLocal || processCalls != 2 || collector.calls != 2 {
		t.Fatalf("assessments=%+v process_calls=%d connection_calls=%d err=%v", assessments, processCalls, collector.calls, err)
	}
}

func TestObserverFailsClosedAfterRepeatedProcessChurn(t *testing.T) {
	root := identity(10, 100)
	collector := &recordingConnectionSnapshotter{errors: []error{processSnapshotChanged(), processSnapshotChanged()}}
	observer, err := NewObserver(root, 8, fixedProcessSnapshotter{snapshot: []Process{{ProcessIdentity: root, ParentID: 1}}}, collector)
	if err != nil {
		t.Fatal(err)
	}
	assessments, err := observer.Observe(nil)
	if assessments != nil || !IsProcessSnapshotChanged(err) || collector.calls != 2 {
		t.Fatalf("assessments=%+v calls=%d err=%v", assessments, collector.calls, err)
	}
}

func TestObserverRejectsUnboundedAssessmentSets(t *testing.T) {
	root := identity(10, 100)
	processes := fixedProcessSnapshotter{snapshot: []Process{{ProcessIdentity: root, ParentID: 1}}}
	for _, test := range []struct {
		expected    []Expected
		local       []LocalEndpoint
		connections []Connection
	}{
		{expected: make([]Expected, MaxExpectedRoutes+1)},
		{local: make([]LocalEndpoint, MaxLocalEndpoints+1)},
		{connections: make([]Connection, DefaultMaxConnections+1)},
	} {
		observer, err := NewObserver(root, 8, processes, &recordingConnectionSnapshotter{result: test.connections})
		if err != nil {
			t.Fatal(err)
		}
		if assessments, err := observer.ObserveWithLocalEndpoints(test.expected, test.local); err == nil || assessments != nil {
			t.Fatalf("unbounded assessment input accepted: assessments=%d err=%v", len(assessments), err)
		}
	}
}
