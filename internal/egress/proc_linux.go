//go:build linux

package egress

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const maxProcStatBytes = 4096

type LinuxProcCollector struct {
	Root         string
	MaxProcesses int
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
	if !filepath.IsAbs(root) || limit < 1 {
		return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "absolute proc root and positive process limit are required")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := make([]Process, 0, min(len(entries), limit))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		if len(result) == limit {
			return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "process snapshot exceeds its limit")
		}
		process, err := readProcStat(filepath.Join(root, entry.Name(), "stat"), pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, process)
	}
	if len(result) == 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "collect process snapshot", "process snapshot is empty")
	}
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
