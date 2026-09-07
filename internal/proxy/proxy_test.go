package proxy

import (
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

func TestLogThrottledSuppressesRepeats(t *testing.T) {
	// reset shared throttler for determinism
	throttle.mu.Lock()
	throttle.last = make(map[string]time.Time)
	throttle.mu.Unlock()

	l := log.New(io.Discard, "", 0)
	logThrottled(l, "k", time.Hour, "first")
	logThrottled(l, "k", time.Hour, "second-suppressed")
	logThrottled(nil, "k2", time.Hour, "nil-logger-no-panic")
	if len(throttle.last) != 1 {
		t.Fatalf("expected 1 throttler entry, got %d", len(throttle.last))
	}
}

func TestBlockPageUsesShadcnDarkStyling(t *testing.T) {
	page := serveBlockPageHTML(nil, errors.New("blocked: test category"))
	for _, want := range []string{
		`class="dark"`,          // dark theme root
		"--card:oklch(0.205",    // preset dark card token
		"--destructive:oklch(",  // preset destructive token
		"badge-outline",         // real badge variant
		"otu",                   // otu branding, no legacy name
		"<svg",                  // lucide shield icon, no emoji
	} {
		if !strings.Contains(page, want) {
			t.Errorf("block page missing %q", want)
		}
	}
	for _, banned := range []string{"opentunnel", "🚫", "ISP"} {
		if strings.Contains(page, banned) {
			t.Errorf("block page must not contain %q", banned)
		}
	}
}
