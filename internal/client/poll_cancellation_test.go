package client

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
	"opentunnel/internal/version"
)

func TestAdmissionPollCancellationStopsBeforeAnyIdentityOrNetworkWork(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() {
		PollTokenStatusContext(ctx, &config.ClientConf{}, &DeviceIdentity{}, nil, nil, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("admission poll retained shutdown work")
	}
	if _, err := os.Lstat(filepath.Join(root, version.ProductName)); !os.IsNotExist(err) {
		t.Fatal("cancelled poll minted state", err)
	}
}

func TestRegistrationCancellationDoesNotCreateIdentityOrSSHKey(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	RegisterWithPanelContext(ctx, &config.ClientConf{}, &DeviceIdentity{})
	if _, err := os.Lstat(filepath.Join(root, version.ProductName)); !os.IsNotExist(err) {
		t.Fatal("cancelled registration created identity state", err)
	}
}

func TestRegistrationAcceptedResponseIsCommittedButNotConnectivity(t *testing.T) {
	if err := registrationResponse(&http.Response{StatusCode: http.StatusAccepted}); err != nil {
		t.Fatal("committed enrollment with pending SSH reconciliation was rejected", err)
	}
	if err := registrationResponse(&http.Response{StatusCode: http.StatusConflict}); !errors.Is(err, errRegistrationIdentityConflict) {
		t.Fatal("identity conflict was hidden", err)
	}
}

func TestStatusCancellationDoesNotFallThroughToPinnedNetwork(t *testing.T) {
	SetControlChannel(func(ctx context.Context, _ protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	t.Cleanup(func() { SetControlChannel(nil) })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, _, _, _, _, err := checkTokenStatusContext(ctx, &config.ClientConf{ServerAddr: "never-contact.invalid:443", Fingerprint: strings.Repeat("a", 64)}, "synthetic-status-token", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancelled status attempted another channel", err)
	}
}

func TestHTTPStatusRequestRetainsCallerCancellation(t *testing.T) {
	cl := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, _, _, _, err := fetchStatusScopedContext(ctx, cl, "https://synthetic.invalid", "synthetic-status-token", false, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("status I/O ignored caller cancellation", err)
	}
}
