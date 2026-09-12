package instance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoreStateRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentveil", "core.json")
	want := State{SchemaVersion: "v1", APIEndpoint: "http://127.0.0.1:43123", ProcessID: 42, StartedAt: time.Now().UTC().Truncate(time.Second)}
	if err := WriteState(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state permissions=%o", info.Mode().Perm())
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("state=%+v want=%+v", got, want)
	}
	if err := RemoveState(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state file remained after cleanup: %v", err)
	}
}

func TestCoreStateRejectsRemoteMalformedAndOversizedData(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "core.json")
	for _, payload := range []string{
		`{"schema_version":"v1","api_endpoint":"https://api.example:443","process_id":1,"started_at":"2026-01-01T00:00:00Z"}`,
		`{"schema_version":"v1","api_endpoint":"http://127.0.0.1:1","process_id":1,"started_at":"2026-01-01T00:00:00Z","token":"secret"}`,
		`{"schema_version":"v1","api_endpoint":"http://127.0.0.1:1","api_endpoint":"http://127.0.0.1:2","process_id":1,"started_at":"2026-01-01T00:00:00Z"}`,
		strings.Repeat("x", maxStateBytes+1),
	} {
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(path); err == nil {
			t.Fatal("unsafe state was accepted")
		}
	}
}

func TestCoreStateRejectsUnsafeFileTypesAndPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "core.json")
	payload := []byte(`{"schema_version":"v1","api_endpoint":"http://127.0.0.1:43123","process_id":42,"started_at":"2026-01-01T00:00:00Z"}`)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("world-readable state file was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("symlinked state file was accepted")
	}
}

func TestCoreStateRejectsUnsafeDirectories(t *testing.T) {
	state := State{SchemaVersion: "v1", APIEndpoint: "http://127.0.0.1:43123", ProcessID: 42, StartedAt: time.Now().UTC()}
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(filepath.Join(wide, "core.json"), state); err == nil {
		t.Fatal("world-accessible state directory was accepted")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := WriteState(filepath.Join(linked, "core.json"), state); err == nil {
		t.Fatal("symlinked state directory was accepted")
	}
}
