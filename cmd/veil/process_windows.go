//go:build windows

package main

import "os/exec"

// CommandContext terminates the direct process on Windows. A Job Object based
// descendant controller is required before Windows protected launch is marked
// verified in the compatibility matrix.
func configureProtectedCommand(command *exec.Cmd) {}
