// otu-reality provisions a private fixed-target profile/config or supervises
// an explicitly supplied verified companion. It never downloads executables,
// edits DNS/firewalls or installs services as a side effect.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/reality"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "otu-reality:", err)
		os.Exit(1)
	}
}
func flags(name string) *flag.FlagSet { f := flag.NewFlagSet(name, flag.ContinueOnError); return f }
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("use provision, inner-identity or serve; explicit private paths required")
	}
	switch args[0] {
	case "provision":
		f := flags("provision")
		endpoint := f.String("endpoint", "", "public relay host:port")
		listen := f.String("listen", "", "explicit Xray server listener")
		cover := f.String("cover", "", "matching TLS fallback host:port")
		name := f.String("server-name", "", "matching cover name")
		target := f.String("target", "127.0.0.1:8082", "fixed opentunnel ingress")
		out := f.String("out-dir", "", "private output directory")
		rate := f.Int64("fallback-bps", 0, "explicit fallback shaping tradeoff (0 off)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected provisioning arguments")
		}
		if *out == "" || !filepath.IsAbs(*out) {
			return errors.New("absolute private out-dir required")
		}
		priv, password, err := reality.GenerateKey()
		if err != nil {
			return err
		}
		id, err := reality.GenerateUUID()
		if err != nil {
			return err
		}
		short, err := reality.GenerateShortID()
		if err != nil {
			return err
		}
		profile := reality.Profile{Version: 1, Endpoint: *endpoint, ServerName: *name, UUID: id, Password: password, ShortID: short, Target: *target}
		if err := profile.Validate(); err != nil {
			return err
		}
		config, err := reality.ServerJSON(reality.ServerParams{Listen: *listen, Target: *target, CoverTarget: *cover, ServerName: *name, PrivateKey: priv, UUIDs: []string{id}, ShortIDs: []string{short}, FallbackRate: *rate})
		if err != nil {
			return err
		}
		if err := privatefile.EnsureDir(*out); err != nil {
			return err
		}
		profileData, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return err
		}
		// No credential output; no overwrite of an existing profile/config.
		if err := privatefile.WriteNew(filepath.Join(*out, "client-profile.json"), profileData); err != nil {
			return err
		}
		if err := privatefile.WriteNew(filepath.Join(*out, "server.json"), config); err != nil {
			return err
		}
		fmt.Println("Private client profile and restricted server config created; no listener started.")
		return nil
	case "serve":
		f := flags("serve")
		exe := f.String("executable", "", "verified patched companion")
		digest := f.String("sha256", "", "expected binary digest")
		path := f.String("config", "", "private server config")
		listen := f.String("listen", "", "explicit bind endpoint")
		target := f.String("target", "127.0.0.1:8082", "fixed opentunnel ingress")
		state := f.String("state-dir", "", "private runtime directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected supervision arguments")
		}
		if *state == "" || !filepath.IsAbs(*state) {
			return errors.New("absolute private state-dir required")
		}
		config, err := privatefile.Read(*path, 64<<10)
		if err != nil {
			return errors.New("server configuration unavailable")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		s, err := reality.Start(ctx, reality.ProcessOptions{Executable: *exe, SHA256: *digest, Config: config, Mode: "server", Listen: *listen, Target: *target, StateDir: *state})
		if err != nil {
			return err
		}
		defer s.Close()
		fmt.Println("Verified fixed-target REALITY companion ready.")
		<-ctx.Done()
		return nil
	case "inner-identity":
		f := flags("inner-identity")
		dir := f.String("out-dir", "", "private relay identity directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected identity provisioning arguments")
		}
		if *dir == "" || !filepath.IsAbs(*dir) {
			return errors.New("absolute private out-dir required")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return err
		}
		now := time.Now()
		cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "opentunnel inner relay"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if err != nil {
			return err
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		pk, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := privatefile.WriteNew(filepath.Join(*dir, "inner-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})); err != nil {
			return err
		}
		if err := privatefile.WriteNew(filepath.Join(*dir, "inner-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		fmt.Println("Inner relay public-key pin:", protocol.PublicKeyPin(leaf))
		return nil
	default:
		return errors.New("unknown subcommand")
	}
}
