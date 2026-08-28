package panel

import (
	"encoding/json"
	"math"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"opentunnel/internal/metrics"
	"opentunnel/internal/version"
)

// cpuPctCache holds the latest relay-host CPU sample (background-sampled so
// the API never blocks on a measurement interval).
var cpuPctCache atomic.Uint64

func init() {
	go func() {
		for {
			if pcts, err := cpu.Percent(2*time.Second, false); err == nil && len(pcts) > 0 {
				cpuPctCache.Store(math.Float64bits(pcts[0]))
			}
			time.Sleep(15 * time.Second)
		}
	}()
}

var processStart = time.Now()

// apiServerHealth reports relay-host infrastructure health for the device
// inventory (the relay itself is device #1 in an ISP NOC view).
func (h *Handler) apiServerHealth(w http.ResponseWriter, r *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	out := map[string]any{
		"version":          version.Version,
		"process_uptime_s": int64(time.Since(processStart).Seconds()),
		"goroutines":       runtime.NumGoroutine(),
		"heap_mb":          float64(ms.HeapAlloc) / (1024 * 1024),
		"active_sessions":  metrics.ActiveSessions(),
		"kill_switch":      h.db.KillSwitch(),
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		out["mem_total_mb"] = vm.Total / (1024 * 1024)
		out["mem_used_pct"] = vm.UsedPercent
	}
	if avg, err := load.Avg(); err == nil && avg != nil {
		out["load_1m"] = avg.Load1
		out["load_5m"] = avg.Load5
		out["load_15m"] = avg.Load15
	}
	if cores, err := cpu.Counts(true); err == nil {
		out["cpu_cores"] = cores
	}
	out["cpu_pct"] = math.Float64frombits(cpuPctCache.Load())
	if uptime, err := host.Uptime(); err == nil {
		out["host_uptime_s"] = uptime
	}
	if info, err := host.Info(); err == nil {
		out["os"] = info.OS
		out["platform"] = info.Platform
		out["kernel"] = info.KernelVersion
	}
	json.NewEncoder(w).Encode(out)
}
