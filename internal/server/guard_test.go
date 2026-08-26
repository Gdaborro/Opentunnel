package server

import (
	"testing"
	"time"
)

func TestGuardPerIPConnectionCap(t *testing.T) {
	g := NewGuard(2, 100, time.Second, time.Minute)

	r1 := g.Acquire("1.2.3.4")
	r2 := g.Acquire("1.2.3.4")
	if r3 := g.Acquire("1.2.3.4"); r3 != nil {
		t.Fatal("third concurrent connection from same IP must be denied")
	}
	r1()
	r2()
	if r4 := g.Acquire("1.2.3.4"); r4 == nil {
		t.Fatal("slot must free after release")
	} else {
		r4()
	}
}

func TestGuardBanAfterAuthFailures(t *testing.T) {
	g := NewGuard(16, 100, 30*time.Millisecond, 200*time.Millisecond)
	ip := "9.9.9.9"

	g.Punish(ip)
	g.Punish(ip)
	if g.Acquire(ip) == nil {
		t.Fatal("two failures (typos) should not ban yet")
	}
	g.Punish(ip) // three strikes → escalating ban
	if g.Acquire(ip) != nil {
		t.Fatal("banned IP must be denied")
	}

	time.Sleep(250 * time.Millisecond) // past banMax
	if g.Acquire(ip) == nil {
		t.Fatal("ban must expire after banMax")
	}
}

func TestGuardIndependentIPs(t *testing.T) {
	g := NewGuard(1, 100, time.Second, time.Minute)
	if g.Acquire("5.5.5.5") == nil {
		t.Fatal("ip A allowed")
	}
	if g.Acquire("6.6.6.6") == nil {
		t.Fatal("ip B must be unaffected by ip A usage")
	}
}
