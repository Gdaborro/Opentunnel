package client

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		current, remote string
		want            bool
	}{
		{"0.9.0", "v0.9.1", true},
		{"0.9.0", "v0.10.0", true},
		{"0.9.0", "v1.0.0", true},
		{"0.9.1", "v0.9.1", false},
		{"0.9.2", "v0.9.1", false},
		{"1.0.0", "v0.9.9", false},
		{"0.9.0", "garbage", false},
		{"dev", "v0.9.1", false},
		{"v0.9.0", "0.9.1", true},
	}
	for _, c := range cases {
		if got := isNewer(c.current, c.remote); got != c.want {
			t.Errorf("isNewer(%q,%q)=%v want %v", c.current, c.remote, got, c.want)
		}
	}
}

func TestExpectedSHA256(t *testing.T) {
	body := "## v0.9.1\n\nFixes.\n\nSHA256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
	want := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if got := expectedSHA256(body); got != want {
		t.Fatalf("got %q", got)
	}
	if got := expectedSHA256("no hash here"); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
	if got := expectedSHA256("sha256: tooshort"); got != "" {
		t.Fatalf("short hash must be rejected, got %q", got)
	}
}
