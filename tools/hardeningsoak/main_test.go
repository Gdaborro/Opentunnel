package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuildInspectionRequiresExactFixtureTagOnWindowsAndOmitsPrivateFlags(t *testing.T) {
	info := &debug.BuildInfo{GoVersion: "go1.27.4", Path: "opentunnel/tools/hardeningsoak", Main: debug.Module{Path: "opentunnel", Version: "(devel)"}}
	for _, tags := range []string{"", "notnetenvfixture", "netenvfixture-other"} {
		info.Settings = []debug.BuildSetting{{Key: "-tags", Value: tags}}
		if _, err := inspectBuild("windows", info); err == nil {
			t.Fatal("Windows production backend accepted", tags)
		}
	}
	info.Settings = []debug.BuildSetting{{Key: "-tags", Value: "other,netenvfixture"}, {Key: "GOOS", Value: "windows"}, {Key: "-ldflags", Value: "SYNTHETIC_PRIVATE_FLAG"}, {Key: "CGO_CFLAGS", Value: "SYNTHETIC_PRIVATE_FLAG"}}
	build, err := inspectBuild("windows", info)
	if err != nil || !build.FixtureTag {
		t.Fatal("exact compile-time fixture tag refused", err)
	}
	raw, err := json.Marshal(build)
	if err != nil || bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_FLAG")) {
		t.Fatal("private build flags were copied to evidence", err)
	}
	info.Settings = append(info.Settings, debug.BuildSetting{Key: "GOOS", Value: "linux"})
	if _, err := inspectBuild("windows", info); err == nil {
		t.Fatal("ambiguous duplicate build settings accepted")
	}
	if _, err := inspectBuild("linux", nil); err == nil {
		t.Fatal("missing build provenance accepted")
	}
}

func TestSourceAndExecutableDigestsAreBoundedAndChecked(t *testing.T) {
	upper := strings.Repeat("AB", 32)
	if got, err := normalizeDigest(upper); err != nil || got != strings.ToLower(upper) {
		t.Fatal(got, err)
	}
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64)} {
		if _, err := normalizeDigest(value); err == nil {
			t.Fatal("invalid caller digest accepted")
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "synthetic-binary")
	payload := []byte("not an executable; hash fixture only")
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	got, size, err := hashExecutable(file)
	if err != nil || got != hashPayload(payload) || size != int64(len(payload)) {
		t.Fatal("digest does not bind exact bytes", got, size, err)
	}
	f, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxExecutableBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashExecutable(file); err == nil {
		t.Fatal("oversized sparse file accepted")
	}
}

func memoryJournal(t *testing.T, slots int) (boundedJournal, map[string][]byte) {
	t.Helper()
	files := map[string][]byte{}
	line, err := json.Marshal(resourceSample{Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	j := boundedJournal{dir: t.TempDir(), slots: make([]journalSlot, slots), maxBytes: int64(3 * (len(line) + 8)), maxLine: maxSampleBytes}
	j.reset = func(path string, data []byte) error { files[path] = bytes.Clone(data); return nil }
	j.append = func(path string, data []byte, expected int64) error {
		if int64(len(files[path])) != expected || expected+int64(len(data)) > j.maxBytes {
			return errors.New("memory journal size mismatch")
		}
		files[path] = append(files[path], data...)
		return nil
	}
	return j, files
}

func TestResourceJournalRotationKeepsExactBoundedDurablePrefix(t *testing.T) {
	for _, slots := range []int{1, 2, maxJournalFiles} {
		t.Run(fmt.Sprint(slots), func(t *testing.T) {
			j, files := memoryJournal(t, slots)
			for seq := int64(1); seq <= 100; seq++ {
				if err := j.appendSample(resourceSample{Sequence: seq}); err != nil {
					t.Fatal("bounded rotation failed", seq, err)
				}
			}
			e := j.manifest()
			retained := int64(0)
			first := int64(101)
			for _, raw := range files {
				if int64(len(raw)) > j.maxBytes {
					t.Fatal("journal exceeded per-file bound")
				}
				for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
					var sample resourceSample
					if err := json.Unmarshal(line, &sample); err != nil {
						t.Fatal("torn counted sample", err)
					}
					retained++
					first = min(first, sample.Sequence)
				}
			}
			if len(files) > slots || e.SamplesWritten != 100 || e.SamplesRetained != retained || e.SamplesDiscarded != 100-retained || e.FirstRetainedSequence != first || e.LastSequence != 100 {
				t.Fatal("journal summary does not delimit retained durable records", e, retained, first)
			}
		})
	}
}

func TestResourceJournalWriteFailureAndInvalidBoundsCannotCountSamples(t *testing.T) {
	j, _ := memoryJournal(t, 2)
	if err := j.appendSample(resourceSample{Sequence: 2}); err == nil || j.written != 0 {
		t.Fatal("out-of-order sample was counted")
	}
	j.append = func(string, []byte, int64) error { return errors.New("synthetic disk failure") }
	if err := j.appendSample(resourceSample{Sequence: 1}); err == nil || j.written != 0 {
		t.Fatal("failed append was counted")
	}
	j.current = -1
	if err := j.appendSample(resourceSample{Sequence: 1}); err == nil {
		t.Fatal("invalid rotation slot was accepted")
	}
}

func TestEvidenceAppendRefusesExternalSizeChangeWithoutOverwriting(t *testing.T) {
	file := filepath.Join(t.TempDir(), "resource-samples-00.jsonl")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := appendEvidenceFile(file, []byte("\nnew"), 0); err == nil {
		t.Fatal("changed evidence file appended")
	}
	raw, err := os.ReadFile(file)
	if err != nil || string(raw) != "original" {
		t.Fatal("failed append overwrote old evidence", err)
	}
	if err := appendEvidenceFile(file, []byte("\nnew"), int64(len(raw))); err != nil {
		t.Fatal("valid bounded append refused", err)
	}
}

func TestOperationOutcomeNeverHidesInvariantOrAllowsPartitionPayloadAtDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		report                      cycleReport
		err, attempt, parent, cause error
		partition                   bool
		requests                    int64
		outcome, category           string
	}{
		{name: "complete", outcome: "completed"},
		{name: "run deadline", err: io.EOF, parent: context.DeadlineExceeded, cause: context.DeadlineExceeded, outcome: "incomplete", category: "run_deadline"},
		{name: "local timeout", err: io.EOF, attempt: context.DeadlineExceeded, outcome: "failed", category: "operation_timeout"},
		{name: "mismatch at deadline", err: errPayloadMismatch, parent: context.DeadlineExceeded, outcome: "failed", category: "payload_mismatch"},
		{name: "bad control at deadline", err: errControlInvariant, parent: context.DeadlineExceeded, outcome: "failed", category: "control_invariant"},
		{name: "partition payload at deadline", report: cycleReport{ReceivedBytes: 1}, err: io.EOF, parent: context.DeadlineExceeded, partition: true, requests: 1, outcome: "failed", category: "partition_allowed_data"},
		{name: "observed partition denial", err: io.EOF, partition: true, requests: 1, outcome: "expected_denial", category: "partition_503_observed_no_payload"},
		{name: "unobserved partition denial", err: io.EOF, partition: true, outcome: "failed", category: "partition_denial_unobserved"},
		{name: "partition stalled", err: context.DeadlineExceeded, attempt: context.DeadlineExceeded, partition: true, requests: 1, outcome: "failed", category: "operation_timeout"},
		{name: "evidence abort", parent: context.Canceled, cause: errors.New("synthetic evidence failure"), outcome: "incomplete", category: "evidence_abort"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome, category := operationOutcome(tc.report, tc.err, tc.attempt, tc.parent, tc.cause, tc.partition, tc.requests)
			if outcome != tc.outcome || category != tc.category {
				t.Fatal(outcome, category)
			}
		})
	}
}

func testRecorder(t *testing.T) *evidenceRecorder {
	t.Helper()
	r := newRecorder(t.TempDir(), evidence{RequestedNS: int64(time.Second), ReleaseGate: "not release certification"}, time.Second, time.Second, func(string, []byte) error { return nil })
	r.journal.append = func(string, []byte, int64) error { return nil }
	r.start(time.Now(), bytes.Repeat([]byte("x"), 65536))
	return r
}

func TestRecorderKeepsPartialWorkIncompleteAndSanitizesFailureText(t *testing.T) {
	r := testRecorder(t)
	r.begin(1, "mixed", 0)
	partial := cycleReport{Stage: "tcp_upload_echo", ReceivedBytes: 10, VerifiedBytes: 5, Operations: operationCounts{Downloads: 1}}
	if err := r.complete(partial, io.EOF, context.DeadlineExceeded, context.DeadlineExceeded, context.DeadlineExceeded, 0); err == nil {
		t.Fatal("deadline-interrupted operation returned a completion")
	}
	e := r.snapshot()
	if e.CompletedCycles != 0 || e.IncompleteCycles != 1 || e.PayloadBytes != 0 || e.VerifiedBytes != 5 || e.ReceivedBytes != 10 || e.Operations.Downloads != 1 {
		t.Fatal("partial attempt misreported as completed", e)
	}
	r = testRecorder(t)
	r.begin(1, "mixed", 0)
	if err := r.complete(cycleReport{Stage: "tcp_download"}, errors.New("SYNTHETIC_PRIVATE_TOKEN"), nil, nil, nil, 0); err == nil {
		t.Fatal("transport error returned success")
	}
	raw, err := json.Marshal(r.snapshot())
	if err != nil || bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_TOKEN")) {
		t.Fatal("raw failure details leaked to evidence", err)
	}
}

func TestRecorderCannotPassPrematureStopGapOrFinalWriteFailure(t *testing.T) {
	r := testRecorder(t)
	if err := r.finish(nil); err == nil || r.snapshot().DurationCompleted {
		t.Fatal("premature stop passed requested duration")
	}
	r = testRecorder(t)
	r.result.DeadlineReached, r.result.CompletedCycles = true, 1
	r.result.Gaps.SampleGaps = 1
	if err := r.finish(nil); err == nil || r.snapshot().DurationCompleted {
		t.Fatal("observation gap passed requested duration")
	}
	r = testRecorder(t)
	r.result.DeadlineReached, r.result.CompletedCycles = true, 1
	writes := 0
	r.write = func(string, []byte) error {
		writes++
		if writes == 1 {
			return errors.New("synthetic final storage failure")
		}
		return nil
	}
	if err := r.finish(nil); err == nil || r.snapshot().DurationCompleted || r.snapshot().Outcome != "failed" || writes != 2 {
		t.Fatal("retry erased failed final publication", writes, err)
	}
}

func TestGapClassificationDistinguishesObservedClockAndSchedulingGaps(t *testing.T) {
	g := classifyGap(time.Second, time.Minute, 10*time.Second, 2*time.Second)
	if !g.SampleGap || !g.ClockGap || g.ClockSkewMS != 59000 {
		t.Fatal(g)
	}
	g = classifyGap(time.Minute, time.Minute, 10*time.Second, 2*time.Second)
	if !g.SampleGap || g.ClockGap {
		t.Fatal(g)
	}
	g = classifyGap(time.Second, time.Second, 10*time.Second, 2*time.Second)
	if g.SampleGap || g.ClockGap {
		t.Fatal(g)
	}
}

func journalDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, query := range []string{"CREATE TABLE authority_reservations(settled INTEGER NOT NULL)", "CREATE TABLE authority_rates(value TEXT)", "CREATE TABLE pool_http_proofs(value TEXT)"} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestJournalMeasurementFailureNeverBecomesEmptyAllClear(t *testing.T) {
	db := journalDB(t)
	if _, err := db.Exec("INSERT INTO authority_reservations VALUES(0),(1),(1); INSERT INTO authority_rates VALUES('SYNTHETIC_PRIVATE_TOKEN'); INSERT INTO pool_http_proofs VALUES('SYNTHETIC_PRIVATE_TOKEN')"); err != nil {
		t.Fatal(err)
	}
	c, err := captureJournalCounts(t.Context(), db)
	if err != nil || !c.Exact || c.Grants != 3 || c.UnsettledGrants != 1 || c.SettledGrants != 2 || c.Rates != 1 || c.Replay != 1 {
		t.Fatal(c, err)
	}
	r := testRecorder(t)
	if err := r.sample(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r.snapshot())
	if err != nil || bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_TOKEN")) {
		t.Fatal("journal measurement selected identity contents", err)
	}
	if _, err := db.Exec("DROP TABLE pool_http_proofs"); err != nil {
		t.Fatal(err)
	}
	if _, err := captureJournalCounts(t.Context(), db); err == nil {
		t.Fatal("failed final query returned an empty all-clear")
	}
}

func TestJournalCardinalityStopsAtCapPlusOneAndRefusesDurationClaim(t *testing.T) {
	db := journalDB(t)
	if _, err := db.Exec("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<9000) INSERT INTO authority_rates SELECT 'synthetic' FROM seq"); err != nil {
		t.Fatal(err)
	}
	c, err := captureJournalCounts(t.Context(), db)
	if err != nil || c.Exact || c.Rates != maxRateRows+1 {
		t.Fatal("cardinality scan was not bounded", c, err)
	}
	r := testRecorder(t)
	if err := r.sample(t.Context(), db); err == nil || evidenceCategory(err) != "cardinality_limit" {
		t.Fatal("cardinality saturation concealed", err)
	}
	if e := r.snapshot(); e.DurationCompleted || e.Outcome != "failed" || e.LastSample.Cardinality.Exact {
		t.Fatal("saturated lower-bound measurement passed", e.Outcome)
	}
}

func TestRecorderConcurrentProgressSnapshotsAndResourceSamples(t *testing.T) {
	db := journalDB(t)
	r := testRecorder(t)
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := int64(1); i <= 25; i++ {
			r.begin(i, "mixed", int(i%2))
			r.stage("complete")
			if err := r.complete(cycleReport{Stage: "complete", VerifiedBytes: 1, ReceivedBytes: 1}, nil, nil, nil, nil, 0); err != nil {
				t.Error(err)
				return
			}
		}
	})
	wg.Go(func() {
		for range 25 {
			if err := r.sample(t.Context(), db); err != nil {
				t.Error(err)
				return
			}
			if _, err := json.Marshal(r.snapshot()); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	if e := r.snapshot(); e.CompletedCycles != 25 || e.PayloadBytes != 25 || e.Journal.SamplesWritten != 25 {
		t.Fatal("concurrent measurement lost progress", e.CompletedCycles, e.Journal.SamplesWritten)
	}
}

func TestBoundConnectionCancellationClosesOnlyItsOwnedStream(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(t.Context())
	closeConn, err := bindConnection(ctx, left, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	cancel()
	done := make(chan error, 1)
	go func() { _, err := left.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled stream stayed readable")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release stream I/O")
	}
}
