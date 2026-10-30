package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/dns/dnsmessage"
)

// buildECHConfig encodes one draft-17 ECHConfig (X25519 / HKDF-SHA256 /
// AES-128-GCM) WITHOUT the list wrapper (the server-key format).
func buildECHConfig(id uint8, pubKey []byte, publicName string) []byte {
	body := []byte{}
	body = append(body, id)
	kem := make([]byte, 2)
	binary.BigEndian.PutUint16(kem, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	body = append(body, kem...)
	plen := make([]byte, 2)
	binary.BigEndian.PutUint16(plen, uint16(len(pubKey)))
	body = append(body, plen...)
	body = append(body, pubKey...)
	body = append(body, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01) // suites: HKDF-SHA256 + AES-128-GCM
	body = append(body, 0x00)                               // max name length
	body = append(body, byte(len(publicName)))
	body = append(body, publicName...)
	body = append(body, 0x00, 0x00) // extensions

	cfg := []byte{0xfe, 0x0d} // version draft-ietf-tls-esni-17/18
	clen := make([]byte, 2)
	binary.BigEndian.PutUint16(clen, uint16(len(body)))
	cfg = append(cfg, clen...)
	return append(cfg, body...)
}

// wrapECHConfigList wraps a single config into the client-side list format.
func wrapECHConfigList(cfg []byte) []byte {
	list := make([]byte, 2)
	binary.BigEndian.PutUint16(list, uint16(len(cfg)))
	return append(list, cfg...)
}

// newECHTestKey builds a config + client list + server private key.
func newECHTestKey(t *testing.T, configID uint8, cover string) (configRaw, list, privKey []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configRaw = buildECHConfig(configID, key.PublicKey().Bytes(), cover)
	return configRaw, wrapECHConfigList(configRaw), key.Bytes()
}

// newTestTLSCfg builds a wstls-shaped stdlib TLS config (dev-insecure,
// no pins): the shape tlsHandshake consumes.
func newTestTLSCfg(sni string) *tls.Config {
	return &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

// newPinnedTestCfg is the same shape with a real pin check.
func newPinnedTestCfg(t *testing.T, sni, hexPin string) *tls.Config {
	t.Helper()
	pin, err := ParseFingerprint(hexPin)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return VerifyPinSet([][]byte{pin}, rawCerts)
		},
	}
}

// TestECHHandshakeAccepted drives tlsHandshake (our exact client flow:
// Chrome parrot + ApplyPreset + ALPN) against a uTLS ECH server and
// asserts the inner SNI arrives while ECH is marked accepted on both ends.
func TestECHHandshakeAccepted(t *testing.T) {
	configRaw, list, priv := newECHTestKey(t, 7, "cover.example.com")

	tmp := t.TempDir()
	srvCert, _, err := LoadOrCreateCert(tmp+"/srv.pem", tmp+"/srv.key", "secret.example.com")
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &utls.Config{
		Certificates: []utls.Certificate{{
			Certificate: srvCert.Certificate,
			PrivateKey:  srvCert.PrivateKey,
		}},
		MinVersion:               utls.VersionTLS13,
		EncryptedClientHelloKeys: []utls.EncryptedClientHelloKey{{Config: configRaw, PrivateKey: priv}},
	}

	type srvResult struct {
		accepted bool
		sni      string
		err      error
	}
	resCh := make(chan srvResult, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resCh <- srvResult{err: err}
			return
		}
		defer c.Close()
		sc := utls.Server(c, srvCfg)
		if err := sc.Handshake(); err != nil {
			resCh <- srvResult{err: err}
			return
		}
		resCh <- srvResult{accepted: sc.ConnectionState().ECHAccepted, sni: sc.ConnectionState().ServerName}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tlsHandshake(ctx, raw, newTestTLSCfg("secret.example.com"), true, list)
	if err != nil {
		t.Fatalf("ECH handshake failed: %v", err)
	}
	if !conn.(*utls.UConn).ConnectionState().ECHAccepted {
		t.Fatal("client ConnectionState.ECHAccepted = false")
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("server handshake: %v", res.err)
		}
		if !res.accepted {
			t.Fatal("server ConnectionState.ECHAccepted = false")
		}
		if res.sni != "secret.example.com" {
			t.Fatalf("server saw SNI %q, want the inner name", res.sni)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server result timeout")
	}
}

// TestECHIgnoredServerRetriesWithoutECH: a server with no ECH support
// keeps the outer (cover) name; its certificate fails our pins, which the
// rejection callback reports — dialTLSWithECH must then retry on a fresh
// socket without ECH, where the real-host certificate matches and the
// session succeeds. Also asserts the provider was told about the rejection.
func TestECHIgnoredServerRetriesWithoutECH(t *testing.T) {
	_, list, _ := newECHTestKey(t, 9, "cover.example.com")

	tmp := t.TempDir()
	coverCert, _, err := LoadOrCreateCert(tmp+"/cover.pem", tmp+"/cover.key", "cover.example.com")
	if err != nil {
		t.Fatal(err)
	}
	realCert, realPin, err := LoadOrCreateCert(tmp+"/real.pem", tmp+"/real.key", "secret.example.com")
	if err != nil {
		t.Fatal(err)
	}

	var seen atomic.Value // last SNI the server's cert callback observed
	srvCfg := &utls.Config{
		MinVersion: utls.VersionTLS12,
		GetCertificate: func(hi *utls.ClientHelloInfo) (*utls.Certificate, error) {
			seen.Store(hi.ServerName)
			if hi.ServerName == "cover.example.com" {
				return &utls.Certificate{Certificate: coverCert.Certificate, PrivateKey: coverCert.PrivateKey}, nil
			}
			return &utls.Certificate{Certificate: realCert.Certificate, PrivateKey: realCert.PrivateKey}, nil
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := utls.Server(c, srvCfg)
				serverErr <- sc.Handshake()
			}(c)
		}
	}()

	var rejected atomic.Int32
	d := &net.Dialer{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTLSWithECH(ctx, d, "tcp", ln.Addr().String(),
		newPinnedTestCfg(t, "secret.example.com", realPin), true,
		func(name string) []byte {
			if name == "secret.example.com" {
				return list
			}
			return nil
		},
		func(name string) {
			if name == "secret.example.com" {
				rejected.Add(1)
			}
		})
	if err != nil {
		t.Fatalf("dialTLSWithECH: %v", err)
	}
	_ = conn.Close()

	if got := rejected.Load(); got != 1 {
		t.Fatalf("rejection hook fired %d times, want 1", got)
	}
	if got, _ := seen.Load().(string); got != "secret.example.com" {
		t.Fatalf("server last saw SNI %q, want the retry without ECH under the real name", got)
	}
	// Exactly one aborted attempt (the ECH try: the client rejects the
	// outer certificate and alerts) and one successful retry.
	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case err := <-serverErr:
			errs = append(errs, err)
		case <-time.After(5 * time.Second):
			t.Fatal("server handshake timeout")
		}
	}
	ok, bad := 0, 0
	for _, e := range errs {
		if e == nil {
			ok++
		} else {
			bad++
		}
	}
	if ok != 1 || bad != 1 {
		t.Fatalf("server handshakes = %v, want one abort (ECH) + one success (retry)", errs)
	}
}

// TestIsECHFallback: rejection classification drives the plain-SNI retry.
func TestIsECHFallback(t *testing.T) {
	if isECHFallback(nil) {
		t.Fatal("nil error must not classify")
	}
	if !isECHFallback(errECHOuterPin) {
		t.Fatal("errECHOuterPin must classify")
	}
	if !isECHFallback(&utls.ECHRejectionError{}) {
		t.Fatal("ECHRejectionError must classify")
	}
	if isECHFallback(context.DeadlineExceeded) {
		t.Fatal("unrelated errors must not classify")
	}
}

// TestParseDoHHTTPSResponse: the DoH reply parser extracts the ECH param
// and TTL, and reports errNoECH for answers without one.
func TestParseDoHHTTPSResponse(t *testing.T) {
	_, list, _ := newECHTestKey(t, 3, "cover.example.com")
	pack := func(withECH bool) []byte {
		res := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("cdn.example.com."),
				Type:  dnsmessage.TypeHTTPS,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
				Priority: 1,
				Target:   dnsmessage.MustNewName("cdn.example.com."),
			}},
		}
		if withECH {
			res.Body.(*dnsmessage.HTTPSResource).SetParam(dnsmessage.SVCParamECH, list)
		}
		msg := dnsmessage.Message{
			Header:  dnsmessage.Header{ID: 0x1234, Response: true},
			Answers: []dnsmessage.Resource{res},
		}
		raw, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	got, ttl, err := parseDoHHTTPSResponse(pack(true), 0x1234)
	if err != nil {
		t.Fatalf("parse with ECH: %v", err)
	}
	if !equalBytes(got, list) {
		t.Fatalf("ECH param = %d bytes, want %d", len(got), len(list))
	}
	if ttl != 300*time.Second {
		t.Fatalf("ttl = %v, want 300s", ttl)
	}

	if _, _, err := parseDoHHTTPSResponse(pack(false), 0x1234); err == nil {
		t.Fatal("answer without ECH must report errNoECH")
	}
	if _, _, err := parseDoHHTTPSResponse(pack(true), 0x9999); err == nil {
		t.Fatal("id mismatch must error")
	}
}

// TestECHProviderLifecycle: cache restore, host gating, rejection backoff
// and fetch recovery.
func TestECHProviderLifecycle(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "ech.json")
	_, list, _ := newECHTestKey(t, 5, "cover.example.com")

	data, err := json.Marshal(echCacheFile{
		Host:      "cdn.example.com",
		List:      base64.StdEncoding.EncodeToString(list),
		FetchedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewECHProvider("cdn.example.com", cache, nil, nil)
	p.Start(ctx)

	if got := p.ConfigFor("cdn.example.com"); !equalBytes(got, list) {
		t.Fatal("cache must be restored at Start")
	}
	if got := p.ConfigFor("other.example.com"); got != nil {
		t.Fatal("config must be host-gated")
	}

	// Rejection for another host is a no-op; for our host it clears.
	p.RejectedFor("other.example.com")
	if p.ConfigFor("cdn.example.com") == nil {
		t.Fatal("other-host rejection must not clear the config")
	}
	p.RejectedFor("cdn.example.com")
	if p.ConfigFor("cdn.example.com") != nil {
		t.Fatal("rejection must clear the config immediately")
	}

	// An injected successful fetch restores and persists.
	p.fetchFn = func(context.Context, string, []string) ([]byte, time.Duration, error) {
		return list, time.Hour, nil
	}
	p.fetchNow(ctx)
	if got := p.ConfigFor("cdn.example.com"); !equalBytes(got, list) {
		t.Fatal("fetch must restore the config")
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not persisted: %v", err)
	}

	// A failed fetch must schedule a distant retry (backoff).
	p.fetchFn = func(context.Context, string, []string) ([]byte, time.Duration, error) {
		return nil, 0, context.DeadlineExceeded
	}
	p.fetchNow(ctx)
	p.mu.Lock()
	next := p.nextTry
	p.mu.Unlock()
	if time.Until(next) < 5*time.Minute {
		t.Fatalf("failed fetch must back off, next try in %v", time.Until(next))
	}
}
