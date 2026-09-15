//go:build darwin

package main

import (
	"regexp"
	"testing"
)

func TestCodexDesktopProcessPatternsUseMacOSCompatibleRegex(t *testing.T) {
	patterns := codexDesktopProcessPatterns(officialCodexDesktopExecutable)
	if len(patterns) != 1 {
		t.Fatalf("patterns=%v", patterns)
	}
	for _, pattern := range patterns {
		if _, err := regexp.CompilePOSIX(pattern); err != nil {
			t.Fatalf("pattern %q is not POSIX ERE: %v", pattern, err)
		}
	}
	if !regexp.MustCompile(patterns[0]).MatchString(officialCodexDesktopExecutable) {
		t.Fatal("main desktop executable was not matched")
	}
	if regexp.MustCompile(patterns[0]).MatchString("/Applications/ChatGPT.app/Contents/Resources/codex app-server --listen stdio://") {
		t.Fatal("standalone app-server was mistaken for the desktop client")
	}
}
