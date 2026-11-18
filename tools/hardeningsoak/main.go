// hardeningsoak exercises synthetic loopback v6 TCP upload/download, UDP and
// control through two TLS-authenticated relays and a central authority. It never
// changes system proxy/DNS/routing, uses fleet credentials or contacts public
// targets. A short run validates the harness, not the mandatory 72-hour gate.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"opentunnel/internal/authority"
	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/metrics"
	"opentunnel/internal/panel"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

const (
	operationTimeout   = 15 * time.Second
	measurementTimeout = 3 * time.Second
	maxExecutableBytes = 512 << 20
	maxSampleBytes     = 16 << 10
	maxJournalFiles    = 16
	maxJournalBytes    = 1 << 20 // per file; at most 16 MiB of retained samples
	maxEvidenceBytes   = 64 << 10
	maxRateRows        = 8192
	maxReplayRows      = 8192
	udpPayload         = "synthetic udp echo"
)

var (
	errPayloadMismatch  = errors.New("payload mismatch")
	errControlInvariant = errors.New("authoritative control invariant failed")
	errHTTPStatus       = errors.New("unexpected synthetic origin HTTP status")
)

type buildProvenance struct {
	GoVersion     string            `json:"go_version"`
	MainPackage   string            `json:"main_package"`
	Module        string            `json:"module"`
	ModuleVersion string            `json:"module_version"`
	FixtureTag    bool              `json:"netenvfixture_build_tag"`
	Settings      map[string]string `json:"allowlisted_build_settings"`
}

type payloadHashes struct {
	Download string `json:"tcp_download_sha256,omitempty"`
	Upload   string `json:"tcp_upload_echo_sha256,omitempty"`
	UDP      string `json:"udp_echo_sha256,omitempty"`
}

type operationCounts struct {
	Downloads int64 `json:"verified_tcp_downloads"`
	Uploads   int64 `json:"verified_tcp_upload_echoes"`
	UDP       int64 `json:"verified_udp_echoes"`
	Control   int64 `json:"verified_approved_status_responses"`
}

func (c *operationCounts) add(other operationCounts) {
	c.Downloads += other.Downloads
	c.Uploads += other.Uploads
	c.UDP += other.UDP
	c.Control += other.Control
}

type cycleReport struct {
	Stage         string          `json:"stage"`
	VerifiedBytes int64           `json:"verified_payload_bytes"`
	ReceivedBytes int64           `json:"received_payload_bytes"`
	Hashes        payloadHashes   `json:"observed_payload_hashes"`
	Operations    operationCounts `json:"operations"`
}

type operationEvidence struct {
	Cycle             int64  `json:"cycle"`
	Kind              string `json:"kind"`
	Relay             int    `json:"relay_index"`
	StartedAtNS       int64  `json:"started_at_unix_ns"`
	FinishedAtNS      int64  `json:"finished_at_unix_ns,omitempty"`
	Outcome           string `json:"outcome"`
	Category          string `json:"category,omitempty"`
	PartitionRequests int64  `json:"observed_partition_503_requests,omitempty"`
	cycleReport
}

type evidence struct {
	SchemaVersion       int                `json:"schema_version"`
	Scope               string             `json:"scope"`
	SourceDigest        string             `json:"source_digest"`
	SourceDigestTrust   string             `json:"source_digest_trust"`
	ExecutableSHA256    string             `json:"executable_sha256"`
	ExecutableBytes     int64              `json:"executable_bytes"`
	Build               buildProvenance    `json:"build"`
	Version             string             `json:"version"`
	Platform            string             `json:"platform"`
	InitializedAt       int64              `json:"initialized_at"`
	StartedAt           int64              `json:"started_at"`
	FinishedAt          int64              `json:"finished_at"`
	RequestedSeconds    int64              `json:"requested_seconds"`
	RequestedNS         int64              `json:"requested_duration_ns"`
	IntervalMS          int64              `json:"cycle_interval_ms"`
	SampleIntervalMS    int64              `json:"resource_sample_interval_ms"`
	ElapsedMS           int64              `json:"observed_monotonic_elapsed_ms"`
	WallElapsedMS       int64              `json:"observed_wall_elapsed_ms"`
	AttemptedCycles     int64              `json:"attempted_cycles"`
	CompletedCycles     int64              `json:"completed_cycles"`
	RelayCompleted      [2]int64           `json:"completed_cycles_by_in_process_relay"`
	FailedCycles        int64              `json:"failed_cycles"`
	IncompleteCycles    int64              `json:"incomplete_cycles"`
	PartitionAttempts   int64              `json:"partition_probe_attempts"`
	PartitionDenied     int64              `json:"partition_probes_failed_closed"`
	PartitionFailed     int64              `json:"partition_probes_failed"`
	PartitionIncomplete int64              `json:"partition_probes_incomplete"`
	PayloadBytes        int64              `json:"payload_bytes"` // verified bytes of completed mixed cycles only
	VerifiedBytes       int64              `json:"verified_payload_bytes_all_attempts"`
	ReceivedBytes       int64              `json:"received_payload_bytes_all_attempts"`
	ExpectedHashes      payloadHashes      `json:"expected_payload_hashes"`
	Operations          operationCounts    `json:"operations_all_attempts"`
	CurrentOperation    *operationEvidence `json:"current_operation,omitempty"`
	LastOperation       *operationEvidence `json:"last_operation,omitempty"`
	FailureCounts       map[string]int64   `json:"failure_categories"`
	IncompleteCounts    map[string]int64   `json:"incomplete_categories"`
	Failure             string             `json:"failure"`
	FailureCategory     string             `json:"failure_category"`
	Outcome             string             `json:"outcome"`
	DeadlineReached     bool               `json:"requested_deadline_reached"`
	DurationCompleted   bool               `json:"requested_duration_completed"`
	Gaps                gapEvidence        `json:"observation_gaps"`
	Journal             journalEvidence    `json:"resource_journal"`
	Baseline            *resourceSample    `json:"resource_baseline,omitempty"`
	LastSample          *resourceSample    `json:"last_resource_sample,omitempty"`
	HighWater           resourceHighWater  `json:"sampled_high_water"`
	ReleaseGate         string             `json:"release_gate"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic soak:", err)
		os.Exit(1)
	}
}
func run(args []string) (retErr error) {
	fs := flag.NewFlagSet("hardeningsoak", flag.ContinueOnError)
	state := fs.String("state-dir", "", "new absolute private directory; never overwrite old evidence")
	duration := fs.Duration("duration", 72*time.Hour, "requested continuous mixed loopback traffic duration")
	interval := fs.Duration("interval", time.Second, "minimum gap per mixed cycle; bounded default stays within central grant journal capacity")
	sampleInterval := fs.Duration("sample-interval", 30*time.Second, "durable resource sample period, 1s..5m; rotating journal is capped at 16 MiB")
	digest := fs.String("source-digest", "", "caller-supplied source inventory SHA256 (not recomputed by this harness)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sourceDigest, err := normalizeDigest(*digest)
	if fs.NArg() != 0 || !filepath.IsAbs(*state) || filepath.Clean(*state) != *state || *duration < time.Second || *duration > 7*24*time.Hour || *interval < 100*time.Millisecond || *interval > time.Minute || *sampleInterval < time.Second || *sampleInterval > 5*time.Minute || err != nil {
		return errors.New("use new absolute --state-dir, --source-digest SHA256, duration 1s..7d, interval 100ms..1m and sample-interval 1s..5m")
	}
	// Check embedded build settings BEFORE any synthetic identity, state or
	// network work. An environment variable cannot enable the fixture backend.
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = nil
	}
	build, err := inspectBuild(runtime.GOOS, info)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve harness executable: %w", err)
	}
	binaryDigest, binaryBytes, err := hashExecutable(executable)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(*state); !os.IsNotExist(err) {
		return errors.New("state directory exists; preserve previous evidence")
	}
	if err := privatefile.EnsureDir(*state); err != nil {
		return err
	}
	now := time.Now()
	recorder := newRecorder(*state, evidence{
		SchemaVersion: 2,
		Scope:         "synthetic loopback only; one shared process/host, central SQL authority + two in-process TLS relays; TCP upload/download, UDP and status",
		SourceDigest:  sourceDigest, SourceDigestTrust: "caller-supplied inventory digest; not recomputed or attested by the harness",
		ExecutableSHA256: binaryDigest, ExecutableBytes: binaryBytes, Build: build,
		Version: version.Version, Platform: runtime.GOOS + "/" + runtime.GOARCH,
		InitializedAt: now.Unix(), RequestedSeconds: int64(duration.Seconds()), RequestedNS: int64(*duration),
		IntervalMS: interval.Milliseconds(), SampleIntervalMS: sampleInterval.Milliseconds(), Outcome: "initializing",
		ReleaseGate: "NOT RELEASE CERTIFICATION: no native-Linux, independent multi-host/carrier, real-device recovery or independent-review evidence",
	}, *sampleInterval, *interval, privatefile.Write)
	var fixture *fixture
	var samplerCancel context.CancelFunc
	var samplerDone chan struct{}
	defer func() {
		if samplerCancel != nil {
			samplerCancel()
			<-samplerDone
		}
		if fixture != nil {
			// A final independent observation catches a delayed final timer (for
			// example host suspend). Do not silently omit it on cancellation.
			if err := recorder.sample(context.Background(), fixture.db.DB); err != nil {
				recorder.fail(evidenceCategory(err), "final resource evidence failed", err)
				retErr = errors.Join(retErr, err)
			}
			fixture.Close()
		}
		retErr = recorder.finish(retErr)
		if retErr == nil {
			e := recorder.snapshot()
			fmt.Printf("Synthetic outcome=%s: %d completed cycles, %d incomplete cycles, %d verified completed-cycle payload bytes; requested_duration_completed=%t. Not release certification.\n", e.Outcome, e.CompletedCycles, e.IncompleteCycles, e.PayloadBytes, e.DurationCompleted)
		}
	}()
	// Persist provenance before fixture creation, and never ignore write errors.
	if err := recorder.writeSummary(); err != nil {
		recorder.fail("evidence_write", "initial evidence write failed", err)
		return err
	}
	oldLocal, hadLocal := os.LookupEnv("LOCALAPPDATA")
	if err := os.Setenv("LOCALAPPDATA", filepath.Join(*state, "synthetic-client")); err != nil {
		recorder.fail("fixture_initialization", "isolated client environment unavailable", err)
		return err
	}
	defer func() {
		var err error
		if hadLocal {
			err = os.Setenv("LOCALAPPDATA", oldLocal)
		} else {
			err = os.Unsetenv("LOCALAPPDATA")
		}
		if err != nil {
			recorder.fail("fixture_initialization", "restore isolated client environment failed", err)
			retErr = errors.Join(retErr, err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	initCtx, initCancel := context.WithTimeout(ctx, 45*time.Second)
	f, err := newFixture(initCtx, *state)
	initCancel()
	if err != nil {
		// Application error strings are not an evidence format: they can
		// include tokens or peer details. Only fixed categories are recorded.
		safeErr := fmt.Errorf("synthetic fixture initialization failed (%s)", failureCategory(err))
		recorder.fail("fixture_initialization", safeErr.Error(), safeErr)
		return safeErr
	}
	fixture = f
	now = time.Now()
	recorder.start(now, fixture.payload)
	deadline, cancelDeadline := context.WithTimeout(ctx, *duration)
	defer cancelDeadline()
	scope, cancel := context.WithCancelCause(deadline)
	defer cancel(nil)
	if err := recorder.sample(scope, fixture.db.DB); err != nil {
		recorder.fail(evidenceCategory(err), "initial resource evidence failed", err)
		return err
	}
	samplerCtx, stopSampler := context.WithCancel(scope)
	samplerCancel, samplerDone = stopSampler, make(chan struct{})
	go func() {
		defer close(samplerDone)
		ticker := time.NewTicker(*sampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-samplerCtx.Done():
				return
			case <-ticker.C:
				if err := recorder.sample(samplerCtx, fixture.db.DB); err != nil {
					if samplerCtx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
						return // final, fresh-context observation follows
					}
					recorder.fail(evidenceCategory(err), "periodic resource evidence failed", err)
					cancel(err)
					return
				}
			}
		}
	}()
	var cycle int64
	for scope.Err() == nil {
		recorder.begin(cycle+1, "mixed", int(cycle%int64(len(fixture.dialers))))
		attempt, stopAttempt := context.WithTimeout(scope, operationTimeout)
		report, cycleErr := fixture.cycle(attempt, int(cycle%int64(len(fixture.dialers))), recorder.stage)
		attemptErr, parentErr := attempt.Err(), scope.Err()
		stopAttempt()
		if err := recorder.complete(report, cycleErr, attemptErr, parentErr, context.Cause(scope), 0); err != nil {
			if errors.Is(parentErr, context.DeadlineExceeded) && !isInvariant(cycleErr) {
				break
			}
			return err
		}
		cycle++
		if cycle%4 == 0 {
			fixture.partition.Store(true)
			before := fixture.partitionRequests.Load()
			recorder.begin(cycle, "partition", int(cycle%int64(len(fixture.dialers))))
			attempt, stopAttempt := context.WithTimeout(scope, operationTimeout)
			report, cycleErr := fixture.cycle(attempt, int(cycle%int64(len(fixture.dialers))), recorder.stage)
			attemptErr, parentErr := attempt.Err(), scope.Err()
			stopAttempt()
			fixture.partition.Store(false)
			if err := recorder.complete(report, cycleErr, attemptErr, parentErr, context.Cause(scope), fixture.partitionRequests.Load()-before); err != nil {
				if errors.Is(parentErr, context.DeadlineExceeded) && !isInvariant(cycleErr) && report.ReceivedBytes == 0 {
					break
				}
				return err
			}
		}
		if cycle%100 == 0 {
			e := recorder.snapshot()
			fmt.Printf("cycles=%d payload_bytes=%d elapsed=%s (synthetic; not release certification)\n", e.CompletedCycles, e.PayloadBytes, time.Since(now).Round(time.Second))
		}
		timer := time.NewTimer(*interval)
		select {
		case <-scope.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if errors.Is(context.Cause(scope), context.DeadlineExceeded) {
		recorder.mu.Lock()
		recorder.result.DeadlineReached = true
		recorder.mu.Unlock()
		return nil // endpoint-interrupted operations remain explicitly incomplete
	}
	err = context.Cause(scope)
	if err == nil {
		err = context.Canceled
	}
	recorder.fail("cancelled", "cancelled before requested duration", err)
	return err
}

func normalizeDigest(value string) (string, error) {
	if len(value) != 2*sha256.Size {
		return "", errors.New("source digest must be exactly 64 hexadecimal characters")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return "", errors.New("source digest must be SHA256 hexadecimal")
	}
	return hex.EncodeToString(raw), nil
}

func inspectBuild(goos string, info *debug.BuildInfo) (buildProvenance, error) {
	var p buildProvenance
	if info == nil || len(info.Settings) > 128 {
		return p, errors.New("harness build provenance unavailable; Windows requires a separately built -tags=netenvfixture binary")
	}
	// Never copy -ldflags, compiler environment flags, replacement paths or
	// arbitrary settings into evidence; those can contain operator secrets.
	allowed := map[string]bool{
		"-buildmode": true, "-compiler": true, "-tags": true, "-trimpath": true,
		"CGO_ENABLED": true, "GOOS": true, "GOARCH": true, "GOAMD64": true,
		"GO386": true, "GOARM": true, "GOARM64": true,
		"vcs": true, "vcs.revision": true, "vcs.time": true, "vcs.modified": true,
	}
	p.Settings = make(map[string]string)
	for _, setting := range info.Settings {
		if !allowed[setting.Key] {
			continue
		}
		if _, exists := p.Settings[setting.Key]; exists || !safeBuildText(setting.Value, 1024) {
			return p, errors.New("invalid or oversized harness build provenance")
		}
		p.Settings[setting.Key] = setting.Value
	}
	for _, tag := range strings.FieldsFunc(p.Settings["-tags"], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if tag == "netenvfixture" {
			p.FixtureTag = true
		}
	}
	if goos == "windows" && !p.FixtureTag {
		return p, errors.New("refusing Windows production backend: build the harness with -tags=netenvfixture before identity or network work")
	}
	for _, value := range []string{info.GoVersion, info.Path, info.Main.Path, info.Main.Version} {
		if !safeBuildText(value, 512) {
			return p, errors.New("invalid harness module provenance")
		}
	}
	p.GoVersion, p.MainPackage, p.Module, p.ModuleVersion = info.GoVersion, info.Path, info.Main.Path, info.Main.Version
	return p, nil
}

func safeBuildText(value string, limit int) bool {
	if len(value) > limit {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func hashExecutable(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("stat harness executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxExecutableBytes {
		return "", 0, errors.New("harness executable must be a regular file of 1..512 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open harness executable: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, errors.New("harness executable changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxExecutableBytes+1))
	if err != nil {
		return "", n, fmt.Errorf("hash harness executable: %w", err)
	}
	after, err := f.Stat()
	if err != nil || n != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", n, errors.New("harness executable changed or exceeded the hashing bound")
	}
	if err := f.Close(); err != nil {
		return "", n, fmt.Errorf("close harness executable: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type gapEvidence struct {
	Interpretation         string `json:"interpretation"`
	SampleThresholdMS      int64  `json:"sample_gap_threshold_ms"`
	ProgressThresholdMS    int64  `json:"progress_gap_threshold_ms"`
	ClockThresholdMS       int64  `json:"clock_disagreement_threshold_ms"`
	SampleGaps             int64  `json:"sample_gaps"`
	ProgressGaps           int64  `json:"progress_gaps"`
	ClockDiscontinuities   int64  `json:"clock_discontinuities"`
	EstimatedMissedSamples int64  `json:"estimated_missed_sample_ticks"`
	MaxObservationGapMS    int64  `json:"max_observation_gap_ms"`
	MaxProgressGapMS       int64  `json:"max_progress_gap_ms"`
	MaxClockDisagreementMS int64  `json:"max_clock_disagreement_ms"`
}

type gapObservation struct {
	MonotonicMS int64 `json:"monotonic_observation_gap_ms"`
	WallMS      int64 `json:"wall_observation_gap_ms"`
	ClockSkewMS int64 `json:"clock_disagreement_ms"`
	SampleGap   bool  `json:"sample_gap"`
	ClockGap    bool  `json:"clock_discontinuity"`
}

func classifyGap(monotonic, wall, sampleThreshold, clockThreshold time.Duration) gapObservation {
	skew := wall - monotonic
	if skew < 0 {
		skew = -skew
	}
	return gapObservation{
		MonotonicMS: monotonic.Milliseconds(), WallMS: wall.Milliseconds(), ClockSkewMS: skew.Milliseconds(),
		SampleGap: max(monotonic, wall) > sampleThreshold, ClockGap: skew > clockThreshold,
	}
}

type runtimeResources struct {
	Goroutines     int    `json:"goroutines"`
	HeapAlloc      uint64 `json:"heap_alloc_bytes"`
	HeapInuse      uint64 `json:"heap_inuse_bytes"`
	HeapSys        uint64 `json:"heap_sys_bytes"`
	HeapObjects    uint64 `json:"heap_objects"`
	TotalAlloc     uint64 `json:"total_alloc_bytes"`
	Sys            uint64 `json:"runtime_sys_bytes"`
	NumGC          uint32 `json:"gc_count"`
	ActiveSessions int64  `json:"process_shared_active_tunnel_sessions"`
}

type sqlResources struct {
	MaxOpenConnections int   `json:"max_open_connections"`
	OpenConnections    int   `json:"open_connections"`
	InUse              int   `json:"in_use"`
	Idle               int   `json:"idle"`
	WaitCount          int64 `json:"wait_count"`
	WaitDurationNS     int64 `json:"wait_duration_ns"`
	MaxIdleClosed      int64 `json:"max_idle_closed"`
	MaxIdleTimeClosed  int64 `json:"max_idle_time_closed"`
	MaxLifetimeClosed  int64 `json:"max_lifetime_closed"`
}

type journalCounts struct {
	Grants          int64 `json:"grant_rows"`
	UnsettledGrants int64 `json:"unsettled_grant_rows"`
	SettledGrants   int64 `json:"settled_grant_rows"`
	Rates           int64 `json:"rate_rows"`
	Replay          int64 `json:"http_proof_replay_rows"`
	GrantLimit      int64 `json:"grant_scan_limit"`
	RateLimit       int64 `json:"rate_scan_limit"`
	ReplayLimit     int64 `json:"replay_scan_limit"`
	Exact           bool  `json:"counts_exact"`
}

// Scan only fixed tables, at most each configured cap plus one row. No
// credentials/identifiers/SQL row contents are selected or serialized. Counts
// above a cap are lower bounds, explicitly marked inexact and stop the run.
func captureJournalCounts(ctx context.Context, db *sql.DB) (journalCounts, error) {
	c := journalCounts{GrantLimit: authority.MaxReservations, RateLimit: maxRateRows, ReplayLimit: maxReplayRows}
	// Observe all journals in one bounded transaction, not three unrelated
	// snapshots that can straddle cleanup/reservation commits.
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(settled=0),0),COALESCE(SUM(settled=1),0) FROM (SELECT settled FROM authority_reservations LIMIT ?)`, c.GrantLimit+1).Scan(&c.Grants, &c.UnsettledGrants, &c.SettledGrants); err != nil {
		return c, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM authority_rates LIMIT ?)`, c.RateLimit+1).Scan(&c.Rates); err != nil {
		return c, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM pool_http_proofs LIMIT ?)`, c.ReplayLimit+1).Scan(&c.Replay); err != nil {
		return c, err
	}
	if err := tx.Commit(); err != nil {
		return c, err
	}
	c.Exact = c.Grants <= c.GrantLimit && c.Rates <= c.RateLimit && c.Replay <= c.ReplayLimit
	return c, nil
}

type resourceSample struct {
	Sequence      int64              `json:"sequence"`
	AtNS          int64              `json:"at_unix_ns"`
	ElapsedMS     int64              `json:"monotonic_elapsed_ms"`
	WallElapsedMS int64              `json:"wall_elapsed_ms"`
	MeasurementMS int64              `json:"measurement_ms"`
	Completed     int64              `json:"completed_cycles"`
	Attempted     int64              `json:"attempted_cycles"`
	Incomplete    int64              `json:"incomplete_cycles"`
	VerifiedBytes int64              `json:"verified_payload_bytes_all_attempts"`
	Current       *operationEvidence `json:"current_operation,omitempty"`
	Timing        gapObservation     `json:"timing"`
	Runtime       runtimeResources   `json:"runtime"`
	SQL           sqlResources       `json:"sql_db_stats"`
	Cardinality   journalCounts      `json:"authority_journals"`
}

type resourceHighWater struct {
	Goroutines     int    `json:"goroutines"`
	HeapAlloc      uint64 `json:"heap_alloc_bytes"`
	HeapInuse      uint64 `json:"heap_inuse_bytes"`
	HeapObjects    uint64 `json:"heap_objects"`
	ActiveSessions int64  `json:"process_shared_active_tunnel_sessions"`
	SQLConnections int    `json:"sql_open_connections"`
	SQLInUse       int    `json:"sql_in_use"`
	GrantRows      int64  `json:"grant_rows"`
	UnsettledRows  int64  `json:"unsettled_grant_rows"`
	RateRows       int64  `json:"rate_rows"`
	ReplayRows     int64  `json:"http_proof_replay_rows"`
}

func (h *resourceHighWater) add(s resourceSample) {
	h.Goroutines = max(h.Goroutines, s.Runtime.Goroutines)
	h.HeapAlloc = max(h.HeapAlloc, s.Runtime.HeapAlloc)
	h.HeapInuse = max(h.HeapInuse, s.Runtime.HeapInuse)
	h.HeapObjects = max(h.HeapObjects, s.Runtime.HeapObjects)
	h.ActiveSessions = max(h.ActiveSessions, s.Runtime.ActiveSessions)
	h.SQLConnections = max(h.SQLConnections, s.SQL.OpenConnections)
	h.SQLInUse = max(h.SQLInUse, s.SQL.InUse)
	h.GrantRows = max(h.GrantRows, s.Cardinality.Grants)
	h.UnsettledRows = max(h.UnsettledRows, s.Cardinality.UnsettledGrants)
	h.RateRows = max(h.RateRows, s.Cardinality.Rates)
	h.ReplayRows = max(h.ReplayRows, s.Cardinality.Replay)
}

type journalEvidence struct {
	FilePattern           string `json:"file_pattern"`
	FileLimit             int    `json:"file_limit"`
	BytesPerFile          int64  `json:"bytes_per_file_limit"`
	BytesPerSample        int    `json:"bytes_per_sample_limit"`
	SamplesWritten        int64  `json:"samples_written"`
	SamplesRetained       int64  `json:"samples_retained"`
	SamplesDiscarded      int64  `json:"samples_discarded_by_rotation"`
	FirstRetainedSequence int64  `json:"first_retained_sequence"`
	LastSequence          int64  `json:"last_sequence"`
}

type journalSlot struct {
	bytes   int64
	records int64
	first   int64
}

type boundedJournal struct {
	dir       string
	slots     []journalSlot
	current   int
	maxBytes  int64
	maxLine   int
	written   int64
	discarded int64
	reset     func(string, []byte) error
	append    func(string, []byte, int64) error
}

func (j *boundedJournal) appendSample(sample resourceSample) error {
	if len(j.slots) < 1 || len(j.slots) > maxJournalFiles || j.current < 0 || j.current >= len(j.slots) || j.maxBytes < 1 || j.maxBytes > maxJournalBytes || j.maxLine < 1 || j.maxLine > maxSampleBytes || j.reset == nil || j.append == nil {
		return errors.New("invalid resource journal bounds")
	}
	if sample.Sequence != j.written+1 {
		return errors.New("resource sample sequence is not the next durable record")
	}
	raw, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > j.maxLine || int64(len(raw)) > j.maxBytes {
		return errors.New("resource sample exceeds the journal line/file bound")
	}
	slot := j.current
	rotate := j.slots[slot].bytes+int64(len(raw)) > j.maxBytes
	if rotate {
		slot = (slot + 1) % len(j.slots)
	}
	path := filepath.Join(j.dir, fmt.Sprintf("resource-samples-%02d.jsonl", slot))
	if rotate || j.slots[slot].records == 0 {
		if err := j.reset(path, nil); err != nil {
			return err
		}
		j.discarded += j.slots[slot].records
		j.slots[slot] = journalSlot{}
		j.current = slot
	}
	if err := j.append(path, raw, j.slots[slot].bytes); err != nil {
		return err
	}
	s := &j.slots[slot]
	if s.records == 0 {
		s.first = sample.Sequence
	}
	s.bytes += int64(len(raw))
	s.records++
	j.written++
	return nil
}

func (j *boundedJournal) manifest() journalEvidence {
	e := journalEvidence{FilePattern: "resource-samples-%02d.jsonl", FileLimit: len(j.slots), BytesPerFile: j.maxBytes, BytesPerSample: j.maxLine, SamplesWritten: j.written, SamplesRetained: j.written - j.discarded, SamplesDiscarded: j.discarded, LastSequence: j.written}
	for _, s := range j.slots {
		if s.records > 0 && (e.FirstRetainedSequence == 0 || s.first < e.FirstRetainedSequence) {
			e.FirstRetainedSequence = s.first
		}
	}
	return e
}

// Each bounded JSONL append is synced and closed before it is counted. Slot
// creation/rotation uses the private atomic, synced writer. A torn final line
// after process/power loss is not evidence of a completed sample; sequence
// numbers and the separately atomic summary delimit the durable prefix.
func appendEvidenceFile(path string, data []byte, expectedSize int64) error {
	if len(data) > maxSampleBytes || expectedSize < 0 || expectedSize+int64(len(data)) > maxJournalBytes {
		return errors.New("evidence append exceeds its bound")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != expectedSize {
		return errors.New("resource evidence file changed or is not regular")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != expectedSize {
		return errors.Join(errors.New("resource evidence changed while opening"), f.Close())
	}
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

type evidenceError struct {
	category string
	err      error
}

func (e *evidenceError) Error() string { return e.category + ": " + e.err.Error() }
func (e *evidenceError) Unwrap() error { return e.err }

func evidenceCategory(err error) string {
	var e *evidenceError
	if errors.As(err, &e) {
		return e.category
	}
	return "measurement"
}

type evidenceRecorder struct {
	mu             sync.Mutex
	result         evidence
	state          string
	write          func(string, []byte) error
	journal        boundedJournal
	started        time.Time
	lastSample     time.Time
	lastProgress   time.Time
	sampleInterval time.Duration
	firstErr       error
}

func newRecorder(state string, result evidence, sampleInterval, interval time.Duration, write func(string, []byte) error) *evidenceRecorder {
	result.FailureCounts, result.IncompleteCounts = make(map[string]int64), make(map[string]int64)
	result.Gaps = gapEvidence{
		Interpretation:      "observed scheduling/suspend/clock gaps, not a diagnosis of host sleep; no observations inside gaps; pauses below thresholds may be missed",
		SampleThresholdMS:   (2*sampleInterval + measurementTimeout + 2*time.Second).Milliseconds(),
		ProgressThresholdMS: (interval + operationTimeout + measurementTimeout + 5*time.Second).Milliseconds(),
		ClockThresholdMS:    (2 * time.Second).Milliseconds(),
	}
	r := &evidenceRecorder{result: result, state: state, write: write, sampleInterval: sampleInterval}
	r.journal = boundedJournal{dir: state, slots: make([]journalSlot, maxJournalFiles), maxBytes: maxJournalBytes, maxLine: maxSampleBytes, reset: write, append: appendEvidenceFile}
	r.result.Journal = r.journal.manifest()
	return r
}

func (r *evidenceRecorder) start(now time.Time, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started, r.lastProgress = now, now
	r.result.StartedAt, r.result.Outcome = now.Unix(), "running"
	r.result.ExpectedHashes = payloadHashes{Download: hashPayload(payload), Upload: hashPayload(payload[:32768]), UDP: hashPayload([]byte(udpPayload))}
}

func (r *evidenceRecorder) markProgressLocked(now time.Time) {
	if !r.lastProgress.IsZero() {
		gap := max(now.Sub(r.lastProgress).Milliseconds(), (now.UnixNano()-r.lastProgress.UnixNano())/int64(time.Millisecond))
		r.result.Gaps.MaxProgressGapMS = max(r.result.Gaps.MaxProgressGapMS, gap)
		if gap > r.result.Gaps.ProgressThresholdMS {
			r.result.Gaps.ProgressGaps++
		}
	}
	r.lastProgress = now
}

func (r *evidenceRecorder) begin(cycle int64, kind string, relay int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.markProgressLocked(now)
	r.result.CurrentOperation = &operationEvidence{Cycle: cycle, Kind: kind, Relay: relay, StartedAtNS: now.UnixNano(), Outcome: "in_progress", cycleReport: cycleReport{Stage: "start"}}
	if kind == "mixed" {
		r.result.AttemptedCycles++
	} else {
		r.result.PartitionAttempts++
	}
}

func (r *evidenceRecorder) stage(stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.markProgressLocked(time.Now())
	if r.result.CurrentOperation != nil {
		r.result.CurrentOperation.Stage = stage
	}
}

func isInvariant(err error) bool {
	return errors.Is(err, errPayloadMismatch) || errors.Is(err, errControlInvariant) || errors.Is(err, errHTTPStatus)
}

func failureCategory(err error) string {
	switch {
	case errors.Is(err, errPayloadMismatch):
		return "payload_mismatch"
	case errors.Is(err, errControlInvariant):
		return "control_invariant"
	case errors.Is(err, errHTTPStatus):
		return "origin_http_status"
	case errors.Is(err, context.DeadlineExceeded):
		return "operation_timeout"
	case errors.Is(err, context.Canceled):
		return "operation_cancelled"
	case errors.Is(err, authority.ErrUnavailable):
		return "authority_unavailable"
	case errors.Is(err, authority.ErrDenied):
		return "authority_denied"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "transport_closed"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "transport_timeout"
	}
	var auth *protocol.AuthError
	var status *protocol.StatusError
	var blocked *client.BlockedError
	var pending *client.PendingError
	if errors.As(err, &auth) || errors.As(err, &status) || errors.As(err, &blocked) || errors.As(err, &pending) {
		return "protocol_or_admission_denial"
	}
	return "transport_or_protocol"
}

func operationOutcome(report cycleReport, err, attemptErr, parentErr, cause error, partition bool, partitionRequests int64) (string, string) {
	// A real invariant violation or received partition payload is never
	// erased merely because a deadline happened at about the same time.
	if partition && (report.ReceivedBytes > 0 || (err == nil && attemptErr == nil && parentErr == nil)) {
		return "failed", "partition_allowed_data"
	}
	if isInvariant(err) {
		return "failed", failureCategory(err)
	}
	if parentErr != nil {
		if errors.Is(parentErr, context.DeadlineExceeded) {
			return "incomplete", "run_deadline"
		}
		if cause != nil && !errors.Is(cause, context.Canceled) {
			return "incomplete", "evidence_abort"
		}
		return "incomplete", "run_cancelled"
	}
	if attemptErr != nil {
		return "failed", failureCategory(attemptErr)
	}
	if err != nil {
		category := failureCategory(err)
		if partition && category != "operation_timeout" && category != "transport_timeout" && category != "operation_cancelled" {
			if partitionRequests > 0 {
				return "expected_denial", "partition_503_observed_no_payload"
			}
			return "failed", "partition_denial_unobserved"
		}
		return "failed", category
	}
	return "completed", ""
}

func (r *evidenceRecorder) complete(report cycleReport, err, attemptErr, parentErr, cause error, partitionRequests int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.markProgressLocked(now)
	op := r.result.CurrentOperation
	if op == nil {
		return errors.New("missing synthetic operation record")
	}
	op.FinishedAtNS, op.cycleReport, op.PartitionRequests = now.UnixNano(), report, partitionRequests
	op.Outcome, op.Category = operationOutcome(report, err, attemptErr, parentErr, cause, op.Kind == "partition", partitionRequests)
	r.result.CurrentOperation, r.result.LastOperation = nil, op
	r.result.VerifiedBytes += report.VerifiedBytes
	r.result.ReceivedBytes += report.ReceivedBytes
	r.result.Operations.add(report.Operations)
	switch op.Outcome {
	case "completed":
		r.result.CompletedCycles++
		r.result.PayloadBytes += report.VerifiedBytes
		r.result.RelayCompleted[op.Relay]++
	case "expected_denial":
		r.result.PartitionDenied++
	case "incomplete":
		if op.Kind == "mixed" {
			r.result.IncompleteCycles++
		} else {
			r.result.PartitionIncomplete++
		}
		r.result.IncompleteCounts[op.Category]++
		if parentErr == nil {
			parentErr = context.Canceled
		}
		return fmt.Errorf("synthetic %s cycle %d incomplete at %s (%s): %w", op.Kind, op.Cycle, report.Stage, op.Category, parentErr)
	case "failed":
		if op.Kind == "mixed" {
			r.result.FailedCycles++
		} else {
			r.result.PartitionFailed++
		}
		safeErr := fmt.Errorf("synthetic %s cycle %d failed at %s (%s)", op.Kind, op.Cycle, report.Stage, op.Category)
		r.failLocked(op.Category, safeErr.Error(), safeErr)
		return safeErr
	}
	if err := r.coverageErrorLocked(); err != nil {
		r.failLocked("observation_gap", "continuous progress not established across an observation gap", err)
		return err
	}
	return r.firstErr
}

func (r *evidenceRecorder) failLocked(category, message string, err error) {
	if r.firstErr == nil {
		r.firstErr = err
	}
	r.result.FailureCounts[category]++
	if r.result.Failure == "" || category == "evidence_write" {
		r.result.FailureCategory, r.result.Failure = category, message
	}
	r.result.DurationCompleted, r.result.Outcome = false, "failed"
}

func (r *evidenceRecorder) fail(category, message string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failLocked(category, message, err)
}

func (r *evidenceRecorder) coverageErrorLocked() error {
	g := r.result.Gaps
	if g.SampleGaps > 0 || g.ProgressGaps > 0 || g.ClockDiscontinuities > 0 {
		return &evidenceError{category: "observation_gap", err: errors.New("host suspend/scheduling or clock gap observed; no continuous-traffic claim")}
	}
	return nil
}

func (r *evidenceRecorder) writeSummaryLocked() error {
	raw, err := json.MarshalIndent(r.result, "", "  ")
	if err != nil {
		return &evidenceError{category: "evidence_write", err: err}
	}
	if len(raw) > maxEvidenceBytes {
		return &evidenceError{category: "evidence_write", err: errors.New("summary evidence exceeds 64 KiB bound")}
	}
	if err := r.write(filepath.Join(r.state, "soak-evidence.json"), raw); err != nil {
		return &evidenceError{category: "evidence_write", err: fmt.Errorf("write soak-evidence.json: %w", err)}
	}
	return nil
}

func (r *evidenceRecorder) writeSummary() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeSummaryLocked()
}

func (r *evidenceRecorder) sample(parent context.Context, db *sql.DB) error {
	begin := time.Now()
	ctx, cancel := context.WithTimeout(parent, measurementTimeout)
	defer cancel()
	counts, err := captureJournalCounts(ctx, db)
	if err != nil {
		return &evidenceError{category: "measurement", err: fmt.Errorf("bounded journal counts: %w", err)}
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	stats := db.Stats()
	now := time.Now()
	s := resourceSample{
		AtNS: now.UnixNano(), MeasurementMS: now.Sub(begin).Milliseconds(), Cardinality: counts,
		Runtime: runtimeResources{Goroutines: runtime.NumGoroutine(), HeapAlloc: mem.HeapAlloc, HeapInuse: mem.HeapInuse, HeapSys: mem.HeapSys, HeapObjects: mem.HeapObjects, TotalAlloc: mem.TotalAlloc, Sys: mem.Sys, NumGC: mem.NumGC, ActiveSessions: metrics.ActiveSessions()},
		SQL:     sqlResources{MaxOpenConnections: stats.MaxOpenConnections, OpenConnections: stats.OpenConnections, InUse: stats.InUse, Idle: stats.Idle, WaitCount: stats.WaitCount, WaitDurationNS: int64(stats.WaitDuration), MaxIdleClosed: stats.MaxIdleClosed, MaxIdleTimeClosed: stats.MaxIdleTimeClosed, MaxLifetimeClosed: stats.MaxLifetimeClosed},
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.IsZero() {
		s.ElapsedMS, s.WallElapsedMS = now.Sub(r.started).Milliseconds(), (now.UnixNano()-r.started.UnixNano())/int64(time.Millisecond)
	}
	if !r.lastSample.IsZero() {
		s.Timing = classifyGap(now.Sub(r.lastSample), time.Duration(now.UnixNano()-r.lastSample.UnixNano()), time.Duration(r.result.Gaps.SampleThresholdMS)*time.Millisecond, time.Duration(r.result.Gaps.ClockThresholdMS)*time.Millisecond)
		g := &r.result.Gaps
		gap := max(s.Timing.MonotonicMS, s.Timing.WallMS)
		g.MaxObservationGapMS = max(g.MaxObservationGapMS, gap)
		g.MaxClockDisagreementMS = max(g.MaxClockDisagreementMS, s.Timing.ClockSkewMS)
		if s.Timing.SampleGap {
			g.SampleGaps++
			g.EstimatedMissedSamples += max(int64(0), gap/r.sampleInterval.Milliseconds()-1)
		}
		if s.Timing.ClockGap {
			g.ClockDiscontinuities++
		}
	}
	r.lastSample = now
	s.Sequence, s.Completed, s.Attempted, s.Incomplete, s.VerifiedBytes = r.journal.written+1, r.result.CompletedCycles, r.result.AttemptedCycles, r.result.IncompleteCycles, r.result.VerifiedBytes
	if r.result.CurrentOperation != nil {
		copy := *r.result.CurrentOperation
		s.Current = &copy
	}
	if err := r.journal.appendSample(s); err != nil {
		return &evidenceError{category: "evidence_write", err: fmt.Errorf("durable resource sample: %w", err)}
	}
	r.result.Journal = r.journal.manifest()
	if r.result.Baseline == nil {
		copy := s
		r.result.Baseline = &copy
	}
	r.result.LastSample = &s
	r.result.HighWater.add(s)
	r.result.ElapsedMS, r.result.WallElapsedMS = s.ElapsedMS, s.WallElapsedMS
	var observationErr error
	if !counts.Exact {
		observationErr = &evidenceError{category: "cardinality_limit", err: errors.New("authority journal exceeds a bounded cardinality scan; recorded counts are lower bounds")}
	} else {
		observationErr = r.coverageErrorLocked()
	}
	if observationErr != nil {
		r.failLocked(evidenceCategory(observationErr), "resource cardinality or observation gap invariant failed", observationErr)
	}
	if err := r.writeSummaryLocked(); err != nil {
		return errors.Join(observationErr, err)
	}
	return observationErr
}

func (r *evidenceRecorder) finish(runErr error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.result.FinishedAt = now.Unix()
	if !r.started.IsZero() {
		r.result.ElapsedMS, r.result.WallElapsedMS = now.Sub(r.started).Milliseconds(), (now.UnixNano()-r.started.UnixNano())/int64(time.Millisecond)
	}
	if runErr != nil && r.result.Failure == "" {
		r.failLocked("cancelled", "run stopped before the requested deadline", runErr)
	}
	if gapErr := r.coverageErrorLocked(); gapErr != nil && r.result.Failure == "" {
		r.failLocked("observation_gap", "continuous progress not established across an observation gap", gapErr)
	}
	if r.result.Failure == "" {
		switch {
		case !r.result.DeadlineReached:
			r.failLocked("incomplete_run", "requested deadline was not reached", errors.New("synthetic run incomplete"))
		case r.result.CompletedCycles == 0:
			r.failLocked("no_completed_cycles", "requested deadline reached without a completed mixed cycle", errors.New("no completed synthetic cycles"))
		case r.result.IncompleteCycles > 0 || r.result.PartitionIncomplete > 0:
			r.result.Outcome = "deadline_reached_with_incomplete_operations"
		default:
			r.result.Outcome, r.result.DurationCompleted = "requested_synthetic_duration_completed", true
		}
	}
	if err := r.writeSummaryLocked(); err != nil {
		r.failLocked("evidence_write", "final evidence write failed; prior durable evidence is incomplete", err)
		// One bounded retry may record the failure if storage recovers. A
		// failed write is never turned into a successful exit by that retry.
		retryErr := r.writeSummaryLocked()
		return errors.Join(runErr, r.firstErr, err, retryErr)
	}
	return errors.Join(runErr, r.firstErr)
}

func (r *evidenceRecorder) snapshot() evidence {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := r.result
	copy.FailureCounts, copy.IncompleteCounts = make(map[string]int64), make(map[string]int64)
	for category, count := range r.result.FailureCounts {
		copy.FailureCounts[category] = count
	}
	for category, count := range r.result.IncompleteCounts {
		copy.IncompleteCounts[category] = count
	}
	if r.result.CurrentOperation != nil {
		op := *r.result.CurrentOperation
		copy.CurrentOperation = &op
	}
	return copy
}

func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

type fixture struct {
	db                *panel.DB
	central           *httptest.Server
	relays            []*httptest.Server
	remotes           []*authority.Client
	dialers           []*client.Adaptive
	origin            *httptest.Server
	udp               net.PacketConn
	partition         atomic.Bool
	partitionRequests atomic.Int64
	payload           []byte
}

func (f *fixture) Close() {
	for _, d := range f.dialers {
		_ = d.Close()
	}
	for _, s := range f.relays {
		s.Close()
	}
	for _, c := range f.remotes {
		_ = c.Close()
	}
	if f.udp != nil {
		_ = f.udp.Close()
	}
	if f.origin != nil {
		f.origin.Close()
	}
	if f.central != nil {
		f.central.Close()
	}
	if f.db != nil {
		_ = f.db.Close()
	}
}

func cert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "synthetic soak"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(8 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, err
}

func newFixture(ctx context.Context, state string) (f *fixture, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f = &fixture{payload: bytes.Repeat([]byte("synthetic-soak-payload"), 8192)}
	success := false
	defer func() {
		if !success {
			f.Close()
		}
	}()
	_, operator, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return f, err
	}
	pool := serverpool.OperatorID(operator.Public().(ed25519.PublicKey))
	f.db, err = panel.Open(filepath.Join(state, "authority.db"), 14)
	if err != nil {
		return f, err
	}
	ph, err := panel.New(f.db, panel.NewAuth(f.db), false).WithServerPoolAuthentication(pool, false, true)
	if err != nil {
		return f, err
	}
	info, err := f.db.BindServerPoolAuthentication(pool, false, true)
	if err != nil {
		return f, err
	}
	identity, err := cert()
	if err != nil {
		return f, err
	}
	credentials := []tls.Certificate{}
	for range 2 {
		c, err := cert()
		if err != nil {
			return f, err
		}
		credentials = append(credentials, c)
	}
	nodeInventory := authority.Nodes{Nodes: []authority.Node{{ID: "node-a", Pins: []string{protocol.PublicKeyPin(credentials[0].Leaf)}}, {ID: "node-b", Pins: []string{protocol.PublicKeyPin(credentials[1].Leaf)}}}}
	ah, err := authority.NewHandler(f.db, info, nodeInventory, ph.Handler())
	if err != nil {
		return f, err
	}
	f.central = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.partition.Load() {
			f.partitionRequests.Add(1)
			http.Error(w, "synthetic partition", 503)
			return
		}
		ah.ServeHTTP(w, r)
	}))
	f.central.TLS, err = authority.ServerTLS(identity, nodeInventory)
	if err != nil {
		return f, err
	}
	f.central.EnableHTTP2 = true
	f.central.Config.ReadHeaderTimeout = 5 * time.Second
	f.central.Config.ReadTimeout = 10 * time.Second
	f.central.Config.WriteTimeout = 10 * time.Second
	f.central.StartTLS()
	nodes := []serverpool.Node{}
	for i := range 2 {
		remote, err := authority.NewClient(authority.ClientOptions{URL: f.central.URL, PoolID: pool, AuthorityID: info.AuthorityID, NodeID: nodeInventory.Nodes[i].ID, Certificate: credentials[i], Pins: []string{protocol.PublicKeyPin(identity.Leaf)}})
		if err != nil {
			return f, err
		}
		f.remotes = append(f.remotes, remote)
		inner, err := cert()
		if err != nil {
			return f, err
		}
		relay := server.Handler(server.Options{PanelDB: remote, PoolID: pool, AuthorityID: info.AuthorityID, InnerTLSCertificate: &inner, RequireInnerTLS: true, RequireChannelAuth: true, AllowRestrictedTargets: true, Logger: log.New(io.Discard, "", 0), Guard: server.NewGuard(16, 128, time.Second, time.Minute), WSPath: "/stream"})
		mux := http.NewServeMux()
		mux.HandleFunc("/api/token/", func(w http.ResponseWriter, r *http.Request) {
			remote.ForwardPublic(w, r, server.ResolveClientIP(r, false))
		})
		mux.Handle("/", relay)
		entry := httptest.NewTLSServer(mux)
		f.relays = append(f.relays, entry)
		nodes = append(nodes, serverpool.Node{ID: nodeInventory.Nodes[i].ID, Name: nodeInventory.Nodes[i].ID, Address: entry.Listener.Addr().String(), Pins: []string{hex.EncodeToString(transport.FingerprintCert(entry.Certificate().Raw))}, InnerTLSPins: []string{protocol.PublicKeyPin(inner.Leaf)}, WSPath: "/stream"})
	}
	now := time.Now()
	profile := serverpool.Profile{Name: "Synthetic hardening soak", AuthorityID: info.AuthorityID, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(8 * 24 * time.Hour).Unix(), ApprovalRequired: true, RequireChannelAuth: true, Nodes: nodes}
	if err := profile.Sign(operator, now); err != nil {
		return f, err
	}
	selector, err := client.NewPoolSelector(profile)
	if err != nil {
		return f, err
	}
	store, err := client.NewPoolTokenStore(pool)
	if err != nil {
		return f, err
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		return f, err
	}
	cfg := &config.ClientConf{Pool: &profile, PoolNode: selector.Current, RequireChannelAuth: true}
	if err := client.EnrollPool(ctx, cfg, device, nil); err != nil {
		return f, err
	}
	if err := f.db.PeerStateAction(device.Token, "approve", "", ""); err != nil {
		return f, err
	}
	for _, node := range nodes {
		one := profile
		one.Nodes = []serverpool.Node{node}
		if err := one.Sign(operator, now); err != nil {
			return f, err
		}
		selector, err := client.NewPoolSelector(one)
		if err != nil {
			return f, err
		}
		d := client.NewAdaptive("", transport.WSTLSOptions{}, "fast", 5*time.Second)
		d.UseTrustedPool(selector)
		d.EnableMux()
		f.dialers = append(f.dialers, d)
	}
	f.origin = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(w, io.LimitReader(r.Body, 1<<20))
			return
		}
		_, _ = w.Write(f.payload)
	}))
	f.origin.Config.ReadHeaderTimeout = 5 * time.Second
	f.origin.Config.ReadTimeout = 10 * time.Second
	f.origin.Config.WriteTimeout = 10 * time.Second
	f.origin.Start()
	f.udp, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return f, err
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := f.udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := f.udp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return
			}
			if _, err := f.udp.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	success = true
	return f, nil
}

// Bound connection I/O to both the operation deadline and its parent. A
// cancelled run closes the active stream, rather than waiting for an unrelated
// transport deadline and falsely calling that tail a completed operation.
func bindConnection(ctx context.Context, conn net.Conn, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return func() {
		stop()
		_ = conn.Close()
	}, nil
}

func (f *fixture) cycle(ctx context.Context, idx int, progress func(string)) (cycleReport, error) {
	var report cycleReport
	stage := func(name string) error {
		report.Stage = name
		if progress != nil {
			progress(name)
		}
		return ctx.Err()
	}
	d := f.dialers[idx]
	host, port, err := net.SplitHostPort(f.origin.Listener.Addr().String())
	if err != nil {
		return report, err
	}
	var n int
	if _, err := fmt.Sscan(port, &n); err != nil {
		return report, err
	}
	target, err := protocol.ParseAddress(host, n)
	if err != nil {
		return report, err
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		name := "tcp_download"
		if method == http.MethodPost {
			name = "tcp_upload_echo"
		}
		if err := stage(name + "_dial"); err != nil {
			return report, err
		}
		conn, err := d.DialTunnel(ctx, target)
		if err != nil {
			return report, err
		}
		closeConn, err := bindConnection(ctx, conn, 10*time.Second)
		if err != nil {
			return report, err
		}
		if err := stage(name + "_transfer"); err != nil {
			closeConn()
			return report, err
		}
		body := []byte{}
		if method == http.MethodPost {
			body = f.payload[:32768]
		}
		_, err = fmt.Fprintf(conn, "%s / HTTP/1.1\r\nHost: fixture\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", method, len(body))
		if err == nil && len(body) > 0 {
			var written int
			written, err = conn.Write(body)
			if err == nil && written != len(body) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			closeConn()
			return report, err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			closeConn()
			return report, err
		}
		expected := f.payload
		if method == http.MethodPost {
			expected = body
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(expected))+1))
		report.ReceivedBytes += int64(len(raw))
		observed := hashPayload(raw)
		if method == http.MethodPost {
			report.Hashes.Upload = observed
		} else {
			report.Hashes.Download = observed
		}
		// Close the stream first: Body.Close must not drain unbounded input.
		closeConn()
		closeErr := response.Body.Close()
		if readErr != nil {
			return report, readErr // partial payload is not a hash invariant failure
		}
		if response.StatusCode != http.StatusOK {
			return report, errHTTPStatus
		}
		if !bytes.Equal(raw, expected) {
			// Early EOF at a deadline is incomplete, not proof of corruption.
			if len(raw) < len(expected) && ctx.Err() != nil {
				return report, ctx.Err()
			}
			return report, errPayloadMismatch
		}
		if closeErr != nil {
			return report, closeErr
		}
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.VerifiedBytes += int64(len(raw))
		if method == http.MethodPost {
			report.Operations.Uploads++
		} else {
			report.Operations.Downloads++
		}
	}
	if err := stage("udp_open"); err != nil {
		return report, err
	}
	udp, err := d.OpenUDPRelay(ctx)
	if err != nil {
		return report, err
	}
	closeUDP, err := bindConnection(ctx, udp, 5*time.Second)
	if err != nil {
		return report, err
	}
	defer closeUDP()
	if err := stage("udp_echo"); err != nil {
		return report, err
	}
	addr := f.udp.LocalAddr().(*net.UDPAddr)
	destination, err := protocol.ParseAddress(addr.IP.String(), addr.Port)
	if err != nil {
		return report, err
	}
	packet := []byte(udpPayload)
	if err := protocol.WriteUDPFrame(udp, destination, packet); err != nil {
		return report, err
	}
	_, payload, err := protocol.ReadUDPFrame(udp)
	report.ReceivedBytes += int64(len(payload))
	if len(payload) > 0 {
		report.Hashes.UDP = hashPayload(payload)
	}
	if err != nil {
		return report, err
	}
	if !bytes.Equal(payload, packet) {
		return report, errPayloadMismatch
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.VerifiedBytes += int64(len(payload))
	report.Operations.UDP++
	closeUDP()
	if err := stage("approved_status"); err != nil {
		return report, err
	}
	// CtrlExchange binds cancellation/deadlines to its own control stream;
	// cancelling one observation must not close another established transfer.
	status, err := d.CtrlExchange(ctx, protocol.CtrlRequest{Op: "status"})
	if err != nil {
		return report, err
	}
	if status == nil || !status.OK || status.Status != "approved" {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		return report, errControlInvariant
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.Operations.Control++
	if err := stage("complete"); err != nil {
		return report, err
	}
	return report, nil
}
