package server

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

// resetSSHBudget clears the process-wide ssh budget store between tests.
func resetSSHBudget(t *testing.T) {
	t.Helper()
	sshBudgetV.mu.Lock()
	sshBudgetV.day = ""
	sshBudgetV.used = nil
	sshBudgetV.mu.Unlock()
}

// TestResolveStreamPolicy: the per-device cap applies on every ingress;
// the ssh-tier cap/budget/trickle apply only when the ssh marker is set,
// and the stricter cap always wins.
func TestResolveStreamPolicy(t *testing.T) {
	const tok = "policy-token"
	cases := []struct {
		name     string
		ingress  string
		stub     killSwitchStub
		seedUsed int64
		wantBps  int64
		wantBud  int64
	}{
		{
			name:    "public ingress ignores ssh policy",
			ingress: "",
			stub:    killSwitchStub{peerMax: 1000, sshMax: 5000, sshDaily: 1 << 20, sshTrickle: 111},
			wantBps: 1000,
		},
		{
			name:    "ssh ingress with no caps is unlimited",
			ingress: IngressSSH,
		},
		{
			name:    "ssh sustained cap applies",
			ingress: IngressSSH,
			stub:    killSwitchStub{sshMax: 2000},
			wantBps: 2000,
		},
		{
			name:    "stricter of peer and ssh caps wins",
			ingress: IngressSSH,
			stub:    killSwitchStub{peerMax: 1000, sshMax: 2000},
			wantBps: 1000,
		},
		{
			name:     "budget counts before exhaustion",
			ingress:  IngressSSH,
			stub:     killSwitchStub{sshMax: 2000, sshDaily: 100, sshTrickle: 111},
			seedUsed: 50,
			wantBps:  2000,
			wantBud:  100,
		},
		{
			name:     "exhausted budget degrades to trickle",
			ingress:  IngressSSH,
			stub:     killSwitchStub{sshDaily: 100, sshTrickle: 111},
			seedUsed: 100,
			wantBps:  111,
			wantBud:  100,
		},
		{
			name:     "exhausted with no trickle falls back to the default rate",
			ingress:  IngressSSH,
			stub:     killSwitchStub{sshDaily: 100},
			seedUsed: 250,
			wantBps:  defaultPostBudgetBps,
			wantBud:  100,
		},
		{
			name:     "trickle never overrides a stricter peer cap",
			ingress:  IngressSSH,
			stub:     killSwitchStub{peerMax: 10000, sshDaily: 100, sshTrickle: 40000},
			seedUsed: 100,
			wantBps:  10000,
			wantBud:  100,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetSSHBudget(t)
			if c.seedUsed > 0 {
				sshBudgetAdd(tok, c.seedUsed)
			}
			got := resolveStreamPolicy(Options{PanelDB: c.stub}, tok, c.ingress)
			if got.limitBps != c.wantBps || got.budgetBytes != c.wantBud {
				t.Fatalf("policy = {bps:%d budget:%d}, want {bps:%d budget:%d}",
					got.limitBps, got.budgetBytes, c.wantBps, c.wantBud)
			}
		})
	}

	// No panel DB / empty token: fully inert.
	resetSSHBudget(t)
	if got := resolveStreamPolicy(Options{}, tok, IngressSSH); got.limitBps != 0 || got.budgetBytes != 0 {
		t.Fatalf("nil panel must be inert, got %+v", got)
	}
}

// TestSSHBudgetRollover: counters accumulate per token within a UTC day
// and reset when the day changes.
func TestSSHBudgetRollover(t *testing.T) {
	var b sshTierBudget
	d1 := time.Date(2026, 10, 29, 23, 59, 0, 0, time.UTC)
	d2 := d1.Add(2 * time.Minute) // crosses UTC midnight

	if got := b.addAt(d1, "tok", 100); got != 100 {
		t.Fatalf("first add = %d, want 100", got)
	}
	if got := b.addAt(d1, "tok", 50); got != 150 {
		t.Fatalf("accumulated = %d, want 150", got)
	}
	if got := b.usedAt(d1, "other"); got != 0 {
		t.Fatalf("unrelated token = %d, want 0", got)
	}
	if got := b.usedAt(d2, "tok"); got != 0 {
		t.Fatalf("post-midnight usage = %d, want 0", got)
	}
	if got := b.addAt(d2, "tok", 7); got != 7 {
		t.Fatalf("new-day add = %d, want 7", got)
	}
}

// TestWithIngressMarker: WithIngress installs the marker the relay's
// policy reads; unmarked requests stay public ("").
func TestWithIngressMarker(t *testing.T) {
	gotCh := make(chan string, 1)
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCh <- ingressFrom(r)
	})

	marked := httptest.NewServer(WithIngress(probe, IngressSSH))
	defer marked.Close()
	if _, err := http.Get(marked.URL); err != nil {
		t.Fatalf("get marked: %v", err)
	}
	select {
	case got := <-gotCh:
		if got != IngressSSH {
			t.Fatalf("marked request ingress = %q, want %q", got, IngressSSH)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe handler never ran")
	}

	plain := httptest.NewServer(probe)
	defer plain.Close()
	if _, err := http.Get(plain.URL); err != nil {
		t.Fatalf("get plain: %v", err)
	}
	select {
	case got := <-gotCh:
		if got != "" {
			t.Fatalf("unmarked request ingress = %q, want empty", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe handler never ran (plain)")
	}
}

// runRelayTransfer pushes one 4 KiB round trip through relayTarget on the
// given ingress and returns once the relay has finished both directions.
func runRelayTransfer(t *testing.T, ingress, token string, stub killSwitchStub) {
	t.Helper()

	// Upstream: echo exactly one 4 KiB chunk, then close — closing is what
	// lets the relay's upstream→client copy finish.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := io.ReadFull(c, buf)
		_, _ = c.Write(buf[:n])
	}()
	upAddr := upLn.Addr().(*net.TCPAddr)

	// Relay I/O pair (same shape as TestRelaySurvivesSlowTransfer).
	rwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rwLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := rwLn.Accept(); err == nil {
			accepted <- c
		}
	}()
	clientEnd, err := net.Dial("tcp", rwLn.Addr().String())
	if err != nil {
		t.Fatalf("relay dial: %v", err)
	}
	defer clientEnd.Close()
	var rw net.Conn
	select {
	case rw = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("relay accept timeout")
	}
	defer rw.Close()

	frame := append([]byte{}, upAddr.IP.To4()...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(upAddr.Port))
	frame = append(frame, port[:]...)
	if _, err := clientEnd.Write(frame); err != nil {
		t.Fatalf("target frame: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTarget(protocol.ATypIPv4, rw.(deadlineRW),
			Options{AllowRestrictedTargets: true, PanelDB: stub},
			token, "approved", "", protocol.ProtoVersionLegacy, ingress)
	}()

	_ = clientEnd.SetDeadline(time.Now().Add(10 * time.Second))
	resp := make([]byte, 2)
	if _, err := io.ReadFull(clientEnd, resp); err != nil {
		t.Fatalf("status read: %v", err)
	}
	if resp[1] != protocol.StatusOK {
		t.Fatalf("connect status = %d, want OK", resp[1])
	}
	payload := make([]byte, 4096)
	if _, err := clientEnd.Write(payload); err != nil {
		t.Fatalf("payload write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(clientEnd, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	_ = clientEnd.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("relayTarget did not finish")
	}
}

// TestSSHIngressBudgetAccounting: a relayed stream counts against the
// device's ssh daily budget only when the ssh marker is present.
func TestSSHIngressBudgetAccounting(t *testing.T) {
	const tok = "budget-token"
	stub := killSwitchStub{sshDaily: 10 << 20} // 10 MB/day, no bandwidth caps

	resetSSHBudget(t)
	runRelayTransfer(t, IngressSSH, tok, stub)
	if used := sshBudgetUsed(tok); used < 4096 {
		t.Fatalf("ssh ingress budget = %d bytes, want >= 4096", used)
	}

	// The same transfer without the marker must not touch the budget.
	resetSSHBudget(t)
	runRelayTransfer(t, "", tok, stub)
	if used := sshBudgetUsed(tok); used != 0 {
		t.Fatalf("public ingress counted %d bytes against the ssh budget", used)
	}
}
