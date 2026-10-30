package client

import "testing"

// TestSSHHostLearningRoundTrip: learned hosts persist across restarts,
// invalid values (schemes, ports, spaces) are ignored, and a wrong value
// can never come from the network side — only the authenticated control
// channel feeds this (see sshhost.go).
func TestSSHHostLearningRoundTrip(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	learnedSSHMu.Lock()
	learnedSSHLoad, learnedSSHHost = false, ""
	learnedSSHMu.Unlock()

	if got := LearnedSSHHost(); got != "" {
		t.Fatalf("fresh store must be empty, got %q", got)
	}

	LearnSSHHost("git.aborro.dev")
	if got := LearnedSSHHost(); got != "git.aborro.dev" {
		t.Fatalf("learned = %q, want git.aborro.dev", got)
	}

	for _, bad := range []string{"https://evil.example", "host:22", "bad host", "", "evil/path", "user@host"} {
		LearnSSHHost(bad)
	}
	if got := LearnedSSHHost(); got != "git.aborro.dev" {
		t.Fatalf("invalid values must not replace the learned host, got %q", got)
	}

	// Simulate a process restart: drop the in-memory cache, reload disk.
	learnedSSHMu.Lock()
	learnedSSHLoad, learnedSSHHost = false, ""
	learnedSSHMu.Unlock()
	if got := LearnedSSHHost(); got != "git.aborro.dev" {
		t.Fatalf("persisted value not reloaded, got %q", got)
	}
}
