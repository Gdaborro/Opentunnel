package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	localproxy "opentunnel/internal/proxy"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// Opt-in LAB soak: real TLS/WS/v5/AEAD/mux plus HTTP(S), SOCKS and UDP on
// loopback. This is not evidence of success on a censored field network.
func TestLocalMixedTrafficSoak(t *testing.T) {
	seconds, _ := strconv.Atoi(os.Getenv("OTU_SOAK_SECONDS"))
	if seconds <= 0 {
		t.Skip("set OTU_SOAK_SECONDS for an explicit local soak")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ts, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := ts.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ts.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	db, err := panel.Open(filepath.Join(t.TempDir(), "soak.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'soak','approved',datetime('now'),datetime('now'),?,'soak')`, device.Token, pub); err != nil {
		t.Fatal(err)
	}
	var identity *tls.Certificate
	if os.Getenv("OTU_SOAK_INNER_TLS") == "1" {
		cert := innerTestCert(t)
		identity = &cert
	}
	relay := httptest.NewTLSServer(server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true, InnerTLSCertificate: identity, RequireInnerTLS: identity != nil}))
	defer relay.Close()
	fp := hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw))
	var carrier transport.Transport = transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: relay.Listener.Addr().String(), Fingerprint: fp, ChromeHello: true})
	if identity != nil {
		carrier, err = client.WithInnerTLS(carrier, []string{protocol.PublicKeyPin(identity.Leaf)})
		if err != nil {
			t.Fatal(err)
		}
	}
	cl := client.NewWithOptions(carrier, client.Options{Token: device.Token, Mux: true, MuxSessions: 2, DialTimeout: 5 * time.Second})
	defer cl.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	go localproxy.ServeHTTPProxy(ctx, httpLn, cl, nil)
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	go localproxy.ServeSOCKS5(ctx, socksLn, cl, nil)
	bulk := bytes.Repeat([]byte{0x5a}, 2<<20)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	defer origin.Close()
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(bulk)))
		_, _ = w.Write(bulk)
	}))
	defer tlsOrigin.Close()
	proxyURL, _ := url.Parse("http://" + httpLn.Addr().String())
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer hc.CloseIdleConnections() // synthetic origin only
	udpOrigin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpOrigin.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := udpOrigin.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpOrigin.WriteToUDP(buf[:n], from)
		}
	}()
	start := time.Now()
	iterations := 0
	var downloaded int64
	peakG := 0
	for time.Since(start) < time.Duration(seconds)*time.Second {
		if iterations > 0 && iterations%10 == 0 {
			relay.CloseClientConnections()
		}
		var failure error
		for attempt := 0; attempt < 3; attempt++ {
			resp, err := hc.Post(origin.URL, "application/octet-stream", bytes.NewReader([]byte("soak post")))
			if err != nil {
				failure = err
				time.Sleep(100 * time.Millisecond)
				continue
			}
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(data) != "soak post" {
				failure = fmt.Errorf("POST body: %v", err)
				continue
			}
			resp, err = hc.Get(tlsOrigin.URL)
			if err != nil {
				failure = err
				continue
			}
			data, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(data, bulk) {
				failure = fmt.Errorf("HTTPS bulk: %v", err)
				continue
			}
			downloaded += int64(len(data))
			respCtrl, err := cl.CtrlExchange(ctx, protocol.CtrlRequest{Op: "status"})
			if err != nil || respCtrl.Status != "approved" {
				failure = fmt.Errorf("control: %v", err)
				continue
			}
			failure = nil
			break
		}
		if failure != nil {
			t.Fatalf("mixed traffic failed after %d iterations: %v", iterations, failure)
		}
		ctrl, err := net.DialTimeout("tcp", socksLn.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = ctrl.Write([]byte{5, 1, 0})
		_, err = io.ReadFull(ctrl, make([]byte, 2))
		if err != nil {
			ctrl.Close()
			t.Fatal(err)
		}
		_, _ = ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
		reply := make([]byte, 10)
		if _, err = io.ReadFull(ctrl, reply); err != nil || reply[1] != 0 {
			ctrl.Close()
			t.Fatalf("UDP association: %v", err)
		}
		app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			ctrl.Close()
			t.Fatal(err)
		}
		_ = app.SetDeadline(time.Now().Add(5 * time.Second))
		var frame bytes.Buffer
		frame.Write([]byte{0, 0, 0})
		addr := udpOrigin.LocalAddr().(*net.UDPAddr)
		target := &protocol.Address{Type: protocol.ATypIPv4, IP: addr.IP, Port: uint16(addr.Port)}
		_ = target.Encode(&frame)
		frame.WriteString("udp soak")
		_, err = app.WriteToUDP(frame.Bytes(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(reply[8])<<8 | int(reply[9])})
		buf := make([]byte, 4096)
		n, _, readErr := app.ReadFromUDP(buf)
		app.Close()
		ctrl.Close()
		if err != nil || readErr != nil || !bytes.HasSuffix(buf[:n], []byte("udp soak")) {
			t.Fatalf("UDP echo: %v %v", err, readErr)
		}
		iterations++
		peakG = max(peakG, runtime.NumGoroutine())
		time.Sleep(time.Second)
	}
	p, err := db.AccessPolicy(device.Token)
	if err != nil || p.UsedBytes < downloaded {
		t.Fatal("incremental accounting did not survive the soak")
	}
	t.Logf("local mixed soak: inner_TLS=%t duration=%s iterations=%d HTTPS_bytes=%d peak_goroutines=%d", identity != nil, time.Since(start).Round(time.Second), iterations, downloaded, peakG)
}
