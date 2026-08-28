package client

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/sensors"

	"opentunnel/internal/config"
	"opentunnel/internal/version"
)

// HealthReporter sends device posture + tunnel quality telemetry to the
// panel (NAC inventory, monitoring dashboards). Probe window is rolling.
type HealthReporter struct {
	cfg    *config.ClientConf
	device *deviceFile
	probe  func(ctx context.Context) (time.Duration, error)

	mu        sync.Mutex
	latencies []time.Duration // recent successful probes (bounded)
	probes    int
	fails     int
}

const probeWindow = 20 // rolling window size for loss/jitter

// NewHealthReporter wires telemetry for one device. probe may be nil
// (tunnel quality fields stay zero).
func NewHealthReporter(cfg *config.ClientConf, device *deviceFile, probe func(ctx context.Context) (time.Duration, error)) *HealthReporter {
	return &HealthReporter{cfg: cfg, device: device, probe: probe}
}

// Start runs the report loop in a goroutine.
func (h *HealthReporter) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		time.Sleep(5 * time.Second) // let the tunnel come up first
		for {
			h.reportOnce()
			time.Sleep(interval)
		}
	}()
}

func (h *HealthReporter) recordProbe(d time.Duration, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.probes++
	if h.probes > probeWindow {
		h.probes = probeWindow
	}
	if err != nil {
		h.fails++
		if h.fails > probeWindow {
			h.fails = probeWindow
		}
		return
	}
	h.latencies = append(h.latencies, d)
	if len(h.latencies) > probeWindow {
		h.latencies = h.latencies[len(h.latencies)-probeWindow:]
	}
}

func (h *HealthReporter) tunnelStats() (latencyMs, jitterMs, lossPct float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.probes > 0 {
		lossPct = 100 * float64(h.fails) / float64(h.probes)
	}
	if len(h.latencies) == 0 {
		return
	}
	last := h.latencies[len(h.latencies)-1]
	latencyMs = float64(last.Milliseconds())
	if len(h.latencies) > 1 {
		var sum float64
		for i := 1; i < len(h.latencies); i++ {
			sum += math.Abs(h.latencies[i].Seconds() - h.latencies[i-1].Seconds())
		}
		jitterMs = 1000 * sum / float64(len(h.latencies)-1)
	}
	return
}

func (h *HealthReporter) reportOnce() {
	payload := map[string]any{
		"token":   h.device.Token,
		"version": version.Version,
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	}

	if pcts, err := cpu.Percent(time.Second, false); err == nil && len(pcts) > 0 {
		payload["cpu_pct"] = math.Round(pcts[0]*10) / 10
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		payload["mem_pct"] = math.Round(vm.UsedPercent*10) / 10
	}
	if temps, err := sensors.TemperaturesWithContext(context.Background()); err == nil {
		var max float64
		for _, t := range temps {
			if t.Temperature > max && t.Temperature < 150 {
				max = t.Temperature
			}
		}
		payload["temp_c"] = max
	}
	if up, err := host.Uptime(); err == nil {
		payload["uptime_s"] = up
	}

	if h.probe != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		d, err := h.probe(ctx)
		cancel()
		h.recordProbe(d, err)
		lat, jit, loss := h.tunnelStats()
		payload["latency_ms"] = lat
		payload["jitter_ms"] = math.Round(jit*10) / 10
		payload["probe_loss_pct"] = math.Round(loss*10) / 10
	}

	body, _ := json.Marshal(payload)
	url := "https://" + h.cfg.ServerAddr + "/api/token/health"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("health: report failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("health: server returned %s", resp.Status)
		return
	}
}
