package authority

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/access"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

func TestAuthorityWireSchemasRoundTrip(t *testing.T) {
	for _, value := range []any{access.Snapshot{Status: "approved", PublicKey: "fixture", Generation: "generation", ChannelRequired: true}, access.Reservation{ID: "fixture", Bytes: 4096, Day: "2026-11-15"}, ControlRequest{Request: protocol.CtrlRequest{Op: "health", CPUPct: 4}}, Settlement{Refund: 3}} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		switch value.(type) {
		case access.Snapshot:
			var dst access.Snapshot
			err = serverpool.DecodeStrict(raw, &dst)
		case access.Reservation:
			var dst access.Reservation
			err = serverpool.DecodeStrict(raw, &dst)
		case ControlRequest:
			var dst ControlRequest
			err = serverpool.DecodeStrict(raw, &dst)
		case Settlement:
			var dst Settlement
			err = serverpool.DecodeStrict(raw, &dst)
		}
		if err != nil {
			t.Fatal("authority wire schema cannot round trip", err)
		}
	}
}

func TestAuthorityNodesMustHaveIsolatedCredentials(t *testing.T) {
	nodes := Nodes{Nodes: []Node{{ID: "node-a", Pins: []string{strings.Repeat("a", 64)}}, {ID: "node-b", Pins: []string{strings.Repeat("a", 64)}}}}
	if nodes.Validate() == nil {
		t.Fatal("shared node credentials accepted")
	}
	nodes.Nodes[1].Pins[0] = strings.Repeat("b", 64)
	if err := nodes.Validate(); err != nil {
		t.Fatal(err)
	}
	id, err := NewReservationID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := ReserveRequest{ID: id, Token: strings.Repeat("t", 32), Generation: "generation", Requested: 4096}
	if err := r.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	if r.Validate(time.Now().Add(ReservationWindow+time.Minute)) == nil {
		t.Fatal("expired grant ID can be newly reserved")
	}
}
