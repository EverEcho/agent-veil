package instance

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestExclusiveCoreLockReleasesCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentveil", "core.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("lock permissions=%o", info.Mode().Perm())
	}
	if _, err := Acquire(path); !hasCode(err, domain.ErrCoreAlreadyRunning) {
		t.Fatalf("second lock error=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Acquire(path)
	if err != nil {
		t.Fatalf("lock was not reusable after release: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOperatingSystemReleasesCoreLockAfterCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentveil", "core.lock")
	command := exec.Command(os.Args[0], "-test.run=TestCoreLockCrashHelper")
	command.Env = append(os.Environ(), "VEIL_LOCK_CRASH_HELPER="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("helper did not acquire lock: line=%q err=%v", line, err)
	}
	if _, err := Acquire(path); !hasCode(err, domain.ErrCoreAlreadyRunning) {
		t.Fatalf("live helper lock was not exclusive: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed helper unexpectedly exited successfully")
	}
	var recovered *Lock
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recovered, err = Acquire(path)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("OS did not release crashed process lock: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCoreLockCrashHelper(t *testing.T) {
	path := os.Getenv("VEIL_LOCK_CRASH_HELPER")
	if path == "" {
		return
	}
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	_, _ = os.Stdout.WriteString("locked\n")
	select {}
}

func TestCoreLockRejectsRelativeAndSymlinkPaths(t *testing.T) {
	if _, err := Acquire("relative.lock"); err == nil {
		t.Fatal("relative lock path accepted")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := Acquire(link); err == nil {
		t.Fatal("symbolic lock path accepted")
	}
}

func TestCoreLockRejectsUnsafeExistingFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "core.lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); err == nil {
		t.Fatal("world-readable lock file was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); err == nil {
		t.Fatal("directory lock path was accepted")
	}
}

func TestCoreLockRejectsUnsafeDirectories(t *testing.T) {
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(filepath.Join(wide, "core.lock")); err == nil {
		t.Fatal("world-accessible lock directory was accepted")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := Acquire(filepath.Join(linked, "core.lock")); err == nil {
		t.Fatal("symlinked lock directory was accepted")
	}
}

func hasCode(err error, code domain.ErrorCode) bool {
	var veil *domain.VeilError
	return errors.As(err, &veil) && veil.Code == code
}
