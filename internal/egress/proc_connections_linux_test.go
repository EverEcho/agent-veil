//go:build linux

package egress

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeTCPTable(t *testing.T, root string, pid int, name, records string) {
	t.Helper()
	directory := filepath.Join(root, strconv.Itoa(pid), "net")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	if err := os.WriteFile(filepath.Join(directory, name), []byte(header+records), 0o600); err != nil {
		t.Fatal(err)
	}
}

func addSocketFD(t *testing.T, root string, pid int, descriptor, inode string) {
	t.Helper()
	directory := filepath.Join(root, strconv.Itoa(pid), "fd")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(directory, descriptor)); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxConnectionCollectorAssociatesSocketWithProcessIdentity(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 10, 1, "agent", 1000)
	addSocketFD(t, root, 10, "3", "12345")
	writeTCPTable(t, root, 10, "tcp", "   0: 0100007F:C001 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	writeTCPTable(t, root, 10, "tcp6", "   0: 00000000000000000000000000000000:C002 0000000000000000FFFF00000100007F:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12346\n")

	connections, err := (LinuxConnectionCollector{Root: root, MaxProcesses: 2, MaxConnections: 2}).Connections([]Process{{ProcessIdentity: identity(10, 1000), ParentID: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 || connections[0].ProcessIdentity != identity(10, 1000) || connections[0].Host != "8.8.8.8" || connections[0].Port != 443 {
		t.Fatalf("connections=%+v", connections)
	}
}

func TestLinuxConnectionCollectorRejectsPIDReuseAndLimits(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 10, 1, "agent", 1000)
	addSocketFD(t, root, 10, "3", "12345")
	if _, err := (LinuxConnectionCollector{Root: root}).Connections([]Process{{ProcessIdentity: identity(10, 999), ParentID: 1}}); err == nil {
		t.Fatal("PID reuse was accepted")
	}
	writeTCPTable(t, root, 10, "tcp", "   0: 0100007F:C001 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if _, err := (LinuxConnectionCollector{Root: root, MaxConnections: 0}).Connections(nil); err == nil {
		t.Fatal("empty process set was accepted")
	}
	if _, err := (LinuxConnectionCollector{Root: "relative"}).Connections([]Process{{ProcessIdentity: identity(10, 1000)}}); err == nil {
		t.Fatal("relative proc root was accepted")
	}
	if _, err := (LinuxConnectionCollector{Root: root, MaxTableRecords: -1}).Connections([]Process{{ProcessIdentity: identity(10, 1000)}}); err == nil {
		t.Fatal("invalid TCP table limit was accepted")
	}
	if _, err := (LinuxConnectionCollector{Root: root, MaxConnections: DefaultMaxConnections + 1}).Connections([]Process{{ProcessIdentity: identity(10, 1000)}}); err == nil {
		t.Fatal("unbounded connection limit was accepted")
	}
}

func TestReadLinuxTCPTableEnforcesBoundsAndAllowsUnownedTimeWait(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, 10, 1, "agent", 1000)
	records := "   0: 0100007F:C001 08080808:01BB 06 00000000:00000000 00:00000000 00000000 1000 0 0\n" +
		"   1: 0100007F:C002 01010101:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345\n"
	writeTCPTable(t, root, 10, "tcp", records)
	path := filepath.Join(root, "10", "net", "tcp")
	if _, _, err := readLinuxTCPTable(path, false, 1); err == nil {
		t.Fatal("oversized TCP table was accepted")
	}
	entries, count, err := readLinuxTCPTable(path, false, 2)
	if err != nil || count != 2 || len(entries) != 1 || entries[0].inode != 12345 {
		t.Fatalf("entries=%+v count=%d err=%v", entries, count, err)
	}
}

func TestParseLinuxEndpointSupportsIPv4AndIPv6(t *testing.T) {
	for _, test := range []struct {
		value string
		ipv6  bool
		host  string
		port  uint16
	}{
		{"08080808:01BB", false, "8.8.8.8", 443},
		{"0000000000000000FFFF00000100007F:01BB", true, "127.0.0.1", 443},
	} {
		host, port, err := parseLinuxEndpoint(test.value, test.ipv6)
		if err != nil || host != test.host || port != test.port {
			t.Fatalf("parseLinuxEndpoint(%q)=(%q,%d,%v)", test.value, host, port, err)
		}
	}
	if _, _, err := parseLinuxEndpoint("not-an-endpoint", false); err == nil {
		t.Fatal("malformed endpoint was accepted")
	}
}
