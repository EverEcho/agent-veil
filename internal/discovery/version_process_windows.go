//go:build windows

package discovery

import "os/exec"

// WaitDelay bounds inherited pipe waits on Windows. Full descendant cleanup
// requires a Job Object before Windows discovery can claim process-tree control.
func configureVersionCommand(*exec.Cmd) {}
func cleanupVersionCommand(*exec.Cmd)   {}
