//go:build netenvfixture

package main

import (
	"context"
	"testing"
	"time"
)

func TestMixedFixtureVerifiesBothRelaysPayloadHashesAndObservedPartitionDenial(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", dir)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f, err := newFixture(ctx, dir)
	if err != nil {
		t.Fatal("synthetic fixture could not initialize", failureCategory(err))
	}
	defer f.Close()
	for idx := range 2 {
		report, err := f.cycle(ctx, idx, nil)
		if err != nil {
			t.Fatal("mixed synthetic cycle failed", report.Stage, failureCategory(err))
		}
		if report.Operations != (operationCounts{Downloads: 1, Uploads: 1, UDP: 1, Control: 1}) || report.Hashes.Download != hashPayload(f.payload) || report.Hashes.Upload != hashPayload(f.payload[:32768]) || report.Hashes.UDP != hashPayload([]byte(udpPayload)) || report.VerifiedBytes != int64(len(f.payload)+32768+len(udpPayload)) {
			t.Fatal("mixed cycle did not bind every expected payload", report.Stage)
		}
	}
	f.partition.Store(true)
	before := f.partitionRequests.Load()
	report, err := f.cycle(ctx, 0, nil)
	f.partition.Store(false)
	requests := f.partitionRequests.Load() - before
	outcome, category := operationOutcome(report, err, nil, ctx.Err(), context.Cause(ctx), true, requests)
	if outcome != "expected_denial" || report.ReceivedBytes != 0 || requests == 0 {
		t.Fatal("central partition did not fail closed with observable refusal", outcome, category, report.ReceivedBytes, requests)
	}
	if report, err := f.cycle(ctx, 1, nil); err != nil || report.Operations.Control != 1 {
		t.Fatal("synthetic traffic did not recover after the partition", report.Stage, failureCategory(err))
	}
}
