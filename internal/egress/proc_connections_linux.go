//go:build linux

package egress

import (
	"bufio"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const (
	DefaultMaxConnections  = 4096
	DefaultMaxTableRecords = 65536
	maxProcNetLineBytes    = 4096
)

// LinuxConnectionCollector associates a bounded set of process file
// descriptors with their network-namespace TCP tables. It intentionally
// reports observed IP endpoints; reverse DNS is not evidence that a socket was
// opened for a particular hostname.
type LinuxConnectionCollector struct {
	Root            string
	MaxProcesses    int
	MaxConnections  int
	MaxTableRecords int
}

func (c LinuxConnectionCollector) Connections(processes []Process) ([]Connection, error) {
	root := c.Root
	if root == "" {
		root = "/proc"
	}
	processLimit := c.MaxProcesses
	if processLimit == 0 {
		processLimit = DefaultMaxProcessSnapshot
	}
	connectionLimit := c.MaxConnections
	if connectionLimit == 0 {
		connectionLimit = DefaultMaxConnections
	}
	tableLimit := c.MaxTableRecords
	if tableLimit == 0 {
		tableLimit = DefaultMaxTableRecords
	}
	if !filepath.IsAbs(root) || processLimit < 1 || processLimit > DefaultMaxProcessSnapshot || connectionLimit < 1 || connectionLimit > DefaultMaxConnections || tableLimit < 1 || tableLimit > DefaultMaxTableRecords || len(processes) == 0 || len(processes) > processLimit {
		return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "absolute proc root and bounded process and connection sets are required")
	}

	seenProcesses := make(map[ProcessIdentity]struct{}, len(processes))
	connections := make([]Connection, 0)
	tableRecords := 0
	for _, process := range processes {
		if !validProcessIdentity(process.ProcessIdentity) {
			return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "process identity is invalid")
		}
		if _, duplicate := seenProcesses[process.ProcessIdentity]; duplicate {
			return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "process identity is duplicated")
		}
		seenProcesses[process.ProcessIdentity] = struct{}{}
		processRoot := filepath.Join(root, strconv.Itoa(process.ProcessID))
		if err := verifyProcessIdentity(processRoot, process.ProcessIdentity); err != nil {
			return nil, err
		}

		entries, err := readBoundedDir(filepath.Join(processRoot, "fd"), connectionLimit)
		if err != nil {
			return nil, err
		}
		sockets := make(map[uint64]struct{})
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join(processRoot, "fd", entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if inode, ok := socketInode(target); ok {
				sockets[inode] = struct{}{}
			}
		}

		readTable := false
		for _, name := range []string{"tcp", "tcp6"} {
			tableEntries, records, err := readLinuxTCPTable(filepath.Join(processRoot, "net", name), name == "tcp6", tableLimit-tableRecords)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			readTable = true
			tableRecords += records
			for _, tableEntry := range tableEntries {
				if _, owned := sockets[tableEntry.inode]; !owned {
					continue
				}
				if len(connections) == connectionLimit {
					return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "connection snapshot exceeds its limit")
				}
				connections = append(connections, Connection{ProcessIdentity: process.ProcessIdentity, Host: tableEntry.host, Port: tableEntry.port})
			}
		}
		if !readTable {
			return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "TCP connection tables are unavailable")
		}
		if err := verifyProcessIdentity(processRoot, process.ProcessIdentity); err != nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "process identity changed during collection")
		}
	}

	sort.Slice(connections, func(i, j int) bool {
		if connections[i].ProcessID != connections[j].ProcessID {
			return connections[i].ProcessID < connections[j].ProcessID
		}
		if connections[i].StartedAt != connections[j].StartedAt {
			return connections[i].StartedAt < connections[j].StartedAt
		}
		if connections[i].Host != connections[j].Host {
			return connections[i].Host < connections[j].Host
		}
		return connections[i].Port < connections[j].Port
	})
	return connections, nil
}

func verifyProcessIdentity(processRoot string, expected ProcessIdentity) error {
	current, err := readProcStat(filepath.Join(processRoot, "stat"), expected.ProcessID)
	if err != nil || current.StartedAt != expected.StartedAt {
		return domain.NewError(domain.ErrInvalidContract, "collect process connections", "process exited or its PID was reused")
	}
	return nil
}

func readBoundedDir(path string, limit int) ([]os.DirEntry, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(limit + 1)
	if err != nil {
		return nil, err
	}
	if len(entries) > limit {
		return nil, domain.NewError(domain.ErrInvalidContract, "collect process connections", "process file descriptor set exceeds its limit")
	}
	return entries, nil
}

func socketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
	return inode, err == nil && inode > 0
}

type linuxTCPEntry struct {
	inode uint64
	host  string
	port  uint16
}

func readLinuxTCPTable(path string, ipv6 bool, limit int) ([]linuxTCPEntry, int, error) {
	if limit < 1 {
		return nil, 0, domain.NewError(domain.ErrInvalidContract, "parse process connections", "TCP table exceeds its limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), maxProcNetLineBytes)
	entries := make([]linuxTCPEntry, 0)
	line := 0
	for scanner.Scan() {
		line++
		if line == 1 {
			continue
		}
		if line-1 > limit {
			return nil, 0, domain.NewError(domain.ErrInvalidContract, "parse process connections", "TCP table exceeds its limit")
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return nil, 0, domain.NewError(domain.ErrInvalidContract, "parse process connections", "TCP table record is malformed")
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, 0, domain.NewError(domain.ErrInvalidContract, "parse process connections", "TCP table inode is invalid")
		}
		host, port, err := parseLinuxEndpoint(fields[2], ipv6)
		if err != nil {
			return nil, 0, err
		}
		if inode == 0 || port == 0 || net.ParseIP(host).IsUnspecified() {
			continue
		}
		entries = append(entries, linuxTCPEntry{inode: inode, host: host, port: port})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	if line == 0 {
		return nil, 0, domain.NewError(domain.ErrInvalidContract, "parse process connections", "TCP table header is missing")
	}
	return entries, line - 1, nil
}

func parseLinuxEndpoint(value string, ipv6 bool) (string, uint16, error) {
	addressHex, portHex, ok := strings.Cut(value, ":")
	expectedBytes := 4
	if ipv6 {
		expectedBytes = 16
	}
	address, err := hex.DecodeString(addressHex)
	port, portErr := strconv.ParseUint(portHex, 16, 16)
	if !ok || err != nil || portErr != nil || len(address) != expectedBytes {
		return "", 0, domain.NewError(domain.ErrInvalidContract, "parse process connections", "TCP endpoint is invalid")
	}
	for offset := 0; offset < len(address); offset += 4 {
		address[offset], address[offset+3] = address[offset+3], address[offset]
		address[offset+1], address[offset+2] = address[offset+2], address[offset+1]
	}
	return net.IP(address).String(), uint16(port), nil
}
