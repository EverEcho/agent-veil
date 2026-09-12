//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProtectedCommandUsesIsolatedCancellableProcessGroup(t *testing.T) {
	command := exec.CommandContext(context.Background(), "/bin/true")
	configureProtectedCommand(command)
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.Cancel == nil {
		t.Fatalf("protected command is not group isolated: %+v", command.SysProcAttr)
	}
}

func TestProtectedCommandCancellationKillsDescendants(t *testing.T) {
	command := exec.CommandContext(context.Background(), "/bin/sh", "-c", "sleep 30 & echo $!; wait")
	configureProtectedCommand(command)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || childPID <= 0 {
		t.Fatalf("descendant pid=%q err=%v", line, err)
	}
	if err := command.Cancel(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err = syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant process %d survived group cancellation: %v", childPID, err)
}
