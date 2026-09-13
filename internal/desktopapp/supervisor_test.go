package desktopapp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/session"
)

const desktopTestToken = "01234567890123456789012345678901"

func TestSupervisorAdoptsButDoesNotStopExternalCore(t *testing.T) {
	server, err := core.New(session.NewManager(), desktopTestToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	directory := t.TempDir()
	state := instance.State{SchemaVersion: "v1", APIEndpoint: server.Endpoint(), InstanceID: server.InstanceID(), ProcessID: 1, StartedAt: time.Now().UTC()}
	if err := instance.WriteState(filepath.Join(directory, "core.json"), state); err != nil {
		t.Fatal(err)
	}
	supervisor, err := NewSupervisor(Options{CoreExecutable: filepath.Join(directory, "veil"), ConfigDir: directory, ManagementToken: desktopTestToken, ReadyTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := supervisor.Ensure(context.Background())
	if err != nil || !status.Running || status.Owned || status.Endpoint != server.Endpoint() || status.Sessions != 0 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if stopped, err := supervisor.StopIfIdle(context.Background()); err != nil || stopped {
		t.Fatalf("external Core stop result=%v err=%v", stopped, err)
	}
}

func TestDesktopTokenPersistsPrivately(t *testing.T) {
	directory := t.TempDir()
	first, err := LoadOrCreateToken(directory)
	if err != nil || len(first) < 32 {
		t.Fatalf("token=%q err=%v", first, err)
	}
	second, err := LoadOrCreateToken(directory)
	if err != nil || second != first {
		t.Fatalf("persisted token=%q err=%v", second, err)
	}
	path := filepath.Join(directory, desktopTokenFile)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(directory); err == nil {
		t.Fatal("unsafe desktop token permissions were accepted")
	}
}

func TestAutoStartWritesAndRemovesPlatformEntries(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			auto := AutoStart{GOOS: goos, Home: t.TempDir()}
			executable := filepath.Join(auto.Home, "AgentVeil Desktop")
			if err := auto.Set(true, executable); err != nil {
				t.Fatal(err)
			}
			if !auto.Enabled() {
				t.Fatal("autostart entry was not enabled")
			}
			if err := auto.Set(false, executable); err != nil {
				t.Fatal(err)
			}
			if auto.Enabled() {
				t.Fatal("autostart entry survived removal")
			}
		})
	}
}
