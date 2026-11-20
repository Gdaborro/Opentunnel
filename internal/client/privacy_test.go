package client

import (
	"context"
	"testing"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
)

func TestLocalMinimalTelemetryDoesNotCollectOrProbeHardware(t *testing.T) {
	defer SetControlChannel(nil)
	var observed protocol.CtrlRequest
	SetControlChannel(func(ctx context.Context, req protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
		observed = req
		return &protocol.CtrlResponse{OK: true, TelemetryMode: "minimal"}, nil
	})
	h := NewHealthReporter(&config.ClientConf{Telemetry: "minimal"}, &DeviceIdentity{Token: "synthetic-privacy-token"}, func(context.Context) (time.Duration, error) {
		t.Fatal("privacy-only report probed network unnecessarily")
		return 0, nil
	})
	h.reportWithContext(t.Context())
	if observed.Op != "health" || observed.Version == "" || observed.CPUPct != 0 || observed.MemPct != 0 || observed.TempC != 0 || observed.UptimeS != 0 || observed.LatencyMs != 0 || observed.HostileNet {
		t.Fatal("minimal report included hardware/network posture")
	}
}
