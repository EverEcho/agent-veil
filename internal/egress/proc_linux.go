//go:build linux

package egress

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const maxProcStatBytes = 4096

const DefaultMaxProcDirectoryEntries = 8192

type LinuxProcCollector struct {
	Root         string
	MaxProcesses int
	MaxEntries   int
}

// LinuxProcessIdentity reads the kernel start time for a PID so callers can
// bind later observations to this exact process rather than to a reusable PID.
func LinuxProcessIdentity(procRoot string, processID int) (ProcessIdentity, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if !filepath.IsAbs(procRoot) || processID <= 0 {
		return ProcessIdentity{}, domain.NewError(domain.ErrInvalidContract, "read process identity", "absolute proc root and positive process id are required")
	}
	process, err := readProcStat(filepath.Join(procRoot, strconv.Itoa(processID), "stat"), processID)
	if err != nil {
		return ProcessIdentity{}, err
	}
	return process.ProcessIdentity, nil
}

func (c LinuxProcCollector) Snapshot() ([]Process, error) {
	root := c.Root
	if root == "" {
		root = "/proc"
	}
	limit := c.MaxProcesses
	if limit == 0 {
		limit = DefaultMaxProcessSnapshot
	}
	entryLimit := c.MaxEntries
	if entryLimit == 0 {
		entryLimit = DefaultMaxProcDirectoryEntries
	}
	if !filepath.IsAbs(root) || limit < 1 || limit > DefaultMaxProcessSnapshot || entryLimit < 1 || entryLimit > DefaultMaxProcDirectoryEntries {
		return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "absolute proc root and bounded scan limits are required")
	}
	directory, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	result := make([]Process, 0, min(limit, 256))
	scanned := 0
	for {
		entries, readErr := directory.ReadDir(256)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, readErr
		}
		for _, entry := range entries {
			scanned++
			if scanned > entryLimit {
				return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "proc directory exceeds its scan limit")
			}
			pid, parseErr := strconv.Atoi(entry.Name())
			if parseErr != nil || pid <= 0 || !entry.IsDir() {
				continue
			}
			if len(result) == limit {
				return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "process snapshot exceeds its limit")
			}
			process, statErr := readProcStat(filepath.Join(root, entry.Name(), "stat"), pid)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr != nil {
				return nil, statErr
			}
			result = append(result, process)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if len(result) == 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "process snapshot is empty")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ProcessID < result[j].ProcessID })
	return result, nil
}

func readProcStat(path string, expectedPID int) (Process, error) {
	file, err := os.Open(path)
	if err != nil {
		return Process{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxProcStatBytes+1))
	if err != nil {
		return Process{}, err
	}
	if len(payload) > maxProcStatBytes {
		return Process{}, domain.NewError(domain.ErrInvalidContract, "parse process stat", "process stat exceeds its limit")
	}
	text := strings.TrimSpace(string(payload))
	open := strings.IndexByte(text, '(')
	close := strings.LastIndex(text, ") ")
	if open <= 0 || close <= open || close+2 >= len(text) {
		return Process{}, domain.NewError(domain.ErrInvalidContract, "parse process stat", "process stat framing is invalid")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(text[:open]))
	fields := strings.Fields(text[close+2:])
	if err != nil || pid != expectedPID || len(fields) < 20 || len(fields[0]) != 1 {
		return Process{}, domain.NewError(domain.ErrInvalidContract, "parse process stat", "process stat identity is invalid")
	}
	parentID, parentErr := strconv.Atoi(fields[1])
	startedAt, startErr := strconv.ParseUint(fields[19], 10, 64)
	if parentErr != nil || startErr != nil || parentID < 0 || startedAt == 0 {
		return Process{}, domain.NewError(domain.ErrInvalidContract, "parse process stat", "process stat parent or start time is invalid")
	}
	return Process{ProcessIdentity: ProcessIdentity{ProcessID: pid, StartedAt: startedAt}, ParentID: parentID}, nil
}
