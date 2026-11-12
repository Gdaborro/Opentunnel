package reality

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/transport"
)

func TestSupervisorWillNotAttachToAnotherListener(t *testing.T) {
	binary, digest := labBinary(t)
	p := testProfile(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	config, err := ClientJSON(p, ln.Addr().String(), "otu", strings.Repeat("x", 43))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Start(t.Context(), ProcessOptions{Executable: binary, SHA256: digest, Config: config, Mode: "client", Listen: ln.Addr().String(), Target: p.Target, StateDir: t.TempDir(), ReadyTimeout: time.Second}); err == nil {
		t.Fatal("supervisor treated an existing listener as its child")
	}
}

func TestREALITYCompanionContextCancellationReapsChild(t *testing.T) {
	binary, digest := labBinary(t)
	p := testProfile(t)
	listen := freeEndpoint(t)
	config, _ := ClientJSON(p, listen, "otu", strings.Repeat("x", 43))
	ctx, cancel := context.WithCancel(t.Context())
	s, err := Start(ctx, ProcessOptions{Executable: binary, SHA256: digest, Config: config, Mode: "client", Listen: listen, Target: p.Target, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if ln, err := net.Listen("tcp", listen); err != nil {
		t.Fatal("child survived supervisor cancellation")
	} else {
		_ = ln.Close()
	}
}

func TestManagedCarrierHTTPNeverFollowsTargetRedirect(t *testing.T) {
	binary, digest := labBinary(t)
	cover := localCover(t)
	priv, password, _ := GenerateKey()
	uuid, _ := GenerateUUID()
	short, _ := GenerateShortID()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.1/", http.StatusFound)
	}))
	defer relay.Close()
	target := relay.Listener.Addr().String()
	endpoint := freeEndpoint(t)
	serverConfig, _ := ServerJSON(ServerParams{Listen: endpoint, Target: target, CoverTarget: cover.Listener.Addr().String(), ServerName: "cover.test", PrivateKey: priv, UUIDs: []string{uuid}, ShortIDs: []string{short}, AllowLoopbackCover: true})
	startLab(t, binary, digest, serverConfig, "server", endpoint, target)
	listen := freeEndpoint(t)
	user, pass, _ := LocalAuth()
	config, _ := ClientJSON(Profile{Version: 1, Endpoint: endpoint, ServerName: "cover.test", UUID: uuid, Password: password, ShortID: short, Target: target}, listen, user, pass)
	proc := startLab(t, binary, digest, config, "client", listen, target)
	cl, err := transport.NewCarrierHTTPClient(transport.CarrierOptions{SOCKSAddr: listen, Target: target, SOCKSUser: user, SOCKSPassword: pass, Ready: proc.WaitReady, DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("http://" + target + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 302 {
		t.Fatal("carrier redirect escaped fixed target")
	}
}
