// otu-pool provisions a dedicated operator key and exports credential-free
// trusted-pool profiles. It does not deploy servers or replicate databases.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/panel"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/version"
)

func main() {
	keyPath := flag.String("key", "pool-signing.pem", "dedicated operator profile-signing key (never a release-signing key)")
	generate := flag.Bool("gen-key", false, "create a new operator key without replacing existing files; print its public pool ID")
	printID := flag.Bool("print-id", false, "print only the operator key's public pool ID")
	output := flag.String("export", "", "write a new signed, credential-free profile to this file (never overwrite)")
	cfgPath := flag.String("c", "server.toml", "server configuration for this local approval authority")
	nodesPath := flag.String("nodes", "", "bounded JSON array of explicitly provisioned nodes with their verified TLS pins")
	name := flag.String("name", "", "operator pool display name")
	validity := flag.Duration("valid-for", 30*24*time.Hour, "profile validity; maximum 90 days")
	channelCanary := flag.Bool("require-channel-auth", false, "export a stronger v2 profile for a canary after independent inner TLS is provisioned; does not change authority policy")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("opentunnel pool", version.Version)
		return
	}
	modes := 0
	for _, set := range []bool{*generate, *printID, *output != ""} {
		if set {
			modes++
		}
	}
	if modes != 1 || flag.NArg() != 0 {
		log.Fatal("choose exactly one of --gen-key, --print-id, or --export")
	}
	if *generate {
		id, err := serverpool.GenerateOperatorKey(*keyPath)
		if err != nil {
			log.Fatalf("operator key creation refused: %v", err)
		}
		fmt.Println("Created a dedicated private profile-signing key. Keep it private and back it up locally.")
		fmt.Println("pool_id =", id)
		return
	}
	key, err := serverpool.LoadOperatorKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	defer clear(key)
	id := serverpool.OperatorID(key.Public().(ed25519.PublicKey))
	if *printID {
		fmt.Println(id)
		return
	}
	if *nodesPath == "" || *name == "" || *validity <= 0 || *validity > serverpool.MaxValidity {
		log.Fatal("export needs --nodes, --name, and a validity between one second and 90 days")
	}
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Fatalf("load server config: %v", err)
	}
	if cfg.AuthorityURL != "" {
		log.Fatal("export profiles at the central authority, not from a relay node or copied database")
	}
	if cfg.PoolID != id {
		log.Fatal("server.toml pool_id must match this dedicated operator key; no authority changed")
	}
	if *channelCanary && (cfg.InnerTLSCertFile == "" || cfg.InnerTLSKeyFile == "") {
		log.Fatal("channel-authentication canary needs independently provisioned inner TLS on every relay; no profile exported")
	}
	raw, err := serverpool.ReadDocument(*nodesPath)
	if err != nil {
		log.Fatal("node manifest unavailable, linked or oversized")
	}
	var nodes []serverpool.Node
	if err := serverpool.DecodeStrict(raw, &nodes); err != nil {
		log.Fatal("node manifest must be one credential-free JSON array with exact node fields")
	}
	now := time.Now()
	p := serverpool.Profile{Name: *name, AuthorityID: id, IssuedAt: now.Unix(), ExpiresAt: now.Add(*validity).Unix(), LoginRequired: cfg.EnrollmentLogin, ApprovalRequired: true, RequireChannelAuth: cfg.RequireChannelAuth || *channelCanary, Nodes: nodes}
	if err := p.Sign(key, now); err != nil {
		log.Fatal(err)
	}
	stateDir := os.Getenv("TMPDIR")
	if stateDir == "" {
		stateDir = "/var/lib/opentunnel"
	}
	db, err := panel.Open(filepath.Join(stateDir, "panel.db"), cfg.PurgeAfterDays)
	if err != nil {
		log.Fatalf("local approval database unavailable: %v", err)
	}
	defer db.Close()
	info, err := db.BindServerPoolAuthentication(id, cfg.EnrollmentLogin, cfg.RequireChannelAuth)
	if err != nil {
		log.Fatalf("authority binding refused: %v", err)
	}
	p.AuthorityID = info.AuthorityID
	if err := p.Sign(key, now); err != nil {
		log.Fatal(err)
	}
	if err := serverpool.Export(*output, p, now); err != nil {
		log.Fatalf("profile export refused: %v", err)
	}
	fmt.Printf("Exported %s (%d nodes); expires %s.\n", p.Name, len(nodes), time.Unix(p.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Println("Operator fingerprint:", p.ID)
	fmt.Println("Approval/accounting authority:", p.AuthorityID)
	fmt.Println("Share only this profile, not the private key. Verify the operator fingerprint independently before client import.")
	fmt.Println("Multiple entries must reach this same local authority; copied databases and independent remote relays are not a shared pool.")
}
