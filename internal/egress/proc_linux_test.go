//go:build linux

package egress

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func procStat(pid, parent int, name string, startedAt uint64) string {
	fields := []string{"S", strconv.Itoa(parent)}
	fields = append(fields, strings.Fields(strings.Repeat("0 ", 17))...)
	fields = append(fields, strconv.FormatUint(startedAt, 10))
	return strconv.Itoa(pid) + " (" + name + ") " + strings.Join(fields, " ") + "\n"
}

func writeProcFixture(t *testing.T, root string, pid, parent int, name string, startedAt uint64) {
	t.Helper()
	directory := filepath.Join(root, strconv.Itoa(pid))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "stat"), []byte(procStat(pid, parent, name, startedAt)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxProcCollectorReadsMinimalIdentitySnapshot(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 10, 1, "agent worker", 1000)
	writeProcFixture(t, root, 11, 10, "child) helper", 1100)
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := (LinuxProcCollector{Root: root, MaxProcesses: 4}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 2 || snapshot[0].ProcessID != 10 || snapshot[0].ParentID != 1 || snapshot[0].StartedAt != 1000 || snapshot[1].ProcessID != 11 || snapshot[1].ParentID != 10 || snapshot[1].StartedAt != 1100 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestLinuxProcCollectorRejectsMalformedAndOversizedSnapshots(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 10, 1, "agent", 1000)
	writeProcFixture(t, root, 11, 10, "child", 1100)
	if _, err := (LinuxProcCollector{Root: root, MaxProcesses: 1}).Snapshot(); err == nil {
		t.Fatal("oversized process snapshot was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "10", "stat"), []byte("10 malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (LinuxProcCollector{Root: root, MaxProcesses: 4}).Snapshot(); err == nil {
		t.Fatal("malformed process stat was accepted")
	}
	if _, err := (LinuxProcCollector{Root: "relative", MaxProcesses: 4}).Snapshot(); err == nil {
		t.Fatal("relative proc root was accepted")
	}
}

func TestReadProcStatRejectsPIDMismatchAndOversizedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, []byte(procStat(10, 1, "agent", 1000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProcStat(path, 11); err == nil {
		t.Fatal("mismatched PID was accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxProcStatBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProcStat(path, 10); err == nil {
		t.Fatal("oversized stat record was accepted")
	}
}
