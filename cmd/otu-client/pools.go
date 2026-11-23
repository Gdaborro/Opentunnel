package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/serverpool"
)

// Profile-only commands run before crash logs, update recovery, device-key
// creation and Windows network recovery. They cannot start a proxy or tunnel.
func handlePoolCommands(args []string) (bool, error) {
	handled := false
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if name == "pool-import" || name == "pool-list" || name == "pool-select" {
			handled = true
		}
	}
	if !handled {
		return false, nil
	}
	fs := flag.NewFlagSet("trusted server pools", flag.ContinueOnError)
	importPath := fs.String("pool-import", "", "verify and import a signed credential-free profile after explicit operator consent")
	list := fs.Bool("pool-list", false, "list imported profiles and the current selection; no network requests")
	selectID := fs.String("pool-select", "", "select an already imported pool ID, or default; effective on the next client start")
	acceptID := fs.String("accept-pool", "", "with --pool-import: explicitly accept this exact independently verified full operator fingerprint")
	if err := fs.Parse(args); err != nil {
		return true, err
	}
	modes := 0
	for _, selected := range []bool{*importPath != "", *list, *selectID != ""} {
		if selected {
			modes++
		}
	}
	if modes != 1 || fs.NArg() != 0 || (*acceptID != "" && *importPath == "") {
		return true, errors.New("choose one profile command; do not combine it with tunnel/network flags")
	}
	root, err := client.NewTokenStore()
	if err != nil {
		return true, err
	}
	store := serverpool.Store{Dir: root.Dir}
	now := time.Now()
	if *importPath != "" {
		p, err := serverpool.Load(*importPath, now)
		if err != nil {
			return true, err
		}
		fmt.Printf("Pool: %s\nOperator fingerprint: %s\nAuthority: %s\nExpires: %s\n", p.Name, p.ID, p.AuthorityID, time.Unix(p.ExpiresAt, 0).UTC().Format(time.RFC3339))
		fmt.Printf("Enrollment login: %t. Administrator device approval: required.\n", p.LoginRequired)
		fmt.Printf("Connection-bound device authentication required: %t.\n", p.RequireChannelAuth)
		for _, n := range p.Nodes {
			fmt.Printf("  %s: %s (TCP %s), %d explicit TLS pin(s)\n", n.Name, n.Address, n.DialAddr(), len(n.Pins))
		}
		fmt.Println("A self-signature does not prove the operator is trustworthy. Verify the fingerprint independently; this operator can observe relay traffic.")
		accepted := *acceptID
		if accepted == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return true, errors.New("import needs interactive consent, or --accept-pool with the exact independently verified fingerprint")
			}
			fmt.Print("To trust this operator, type its full fingerprint (anything else cancels): ")
			accepted, err = boundedConsoleLine()
			if err != nil {
				return true, err
			}
		}
		if accepted != p.ID {
			return true, errors.New("operator fingerprint was not explicitly accepted; no trust imported")
		}
		if err := store.Import(p, true, now); err != nil {
			return true, err
		}
		fmt.Println("Imported. Existing selection and device identities were not changed.")
		fmt.Println("To use it on the next start: otu-client --pool-select", p.ID)
		return true, nil
	}
	if *selectID != "" {
		if err := store.Select(*selectID, now); err != nil {
			return true, err
		}
		fmt.Println("Selected", *selectID, "for the next start. Stop/restart an already running client to change operators.")
		return true, nil
	}
	selected, err := store.Selected()
	if err != nil {
		return true, err
	}
	pools, err := store.List(now)
	if err != nil {
		return true, err
	}
	mark := " "
	if selected == "default" {
		mark = "*"
	}
	fmt.Printf("%s default — existing client.toml and default device identity\n", mark)
	for _, p := range pools {
		mark = " "
		if selected == p.ID {
			mark = "*"
		}
		state := "valid"
		if p.ExpiresAt <= now.Unix() {
			state = "EXPIRED — import a fresh signed profile"
		}
		fmt.Printf("%s %s — %s; %d nodes; login=%t; %s\n", mark, p.ID, p.Name, len(p.Nodes), p.LoginRequired, state)
	}
	return true, nil
}

func selectedPool(cfg *config.ClientConf, override string) (*client.PoolSelector, error) {
	root, err := client.NewTokenStore()
	if err != nil {
		return nil, err
	}
	store := serverpool.Store{Dir: root.Dir}
	id := override
	if id == "" {
		id, err = store.Selected()
		if err != nil {
			return nil, err
		}
	}
	if id == "default" {
		return nil, nil
	}
	p, err := store.Load(id, time.Now())
	if err != nil {
		return nil, fmt.Errorf("selected pool unavailable; no default/operator fallback: %w", err)
	}
	selector, err := client.NewPoolSelector(p)
	if err != nil {
		return nil, err
	}
	configureTrustedPool(cfg, selector)
	return selector, nil
}

// Only local application settings carry across operator selection. Transport,
// keys, carrier credentials, learned pins and bootstrap flags do not.
func configureTrustedPool(cfg *config.ClientConf, selector *client.PoolSelector) {
	p := selector.Profile()
	n := p.Nodes[0]
	cfg.Pool, cfg.PoolNode = &p, selector.Current
	cfg.ServerAddr, cfg.PoolDialAddress, cfg.ServerIP, cfg.ServerFallbacks = n.Address, n.DialAddr(), "", nil
	cfg.Fingerprint, cfg.Fingerprints, cfg.WSPath = n.Pins[0], append([]string(nil), n.Pins...), n.WSPath
	cfg.Token, cfg.Transport, cfg.Insecure, cfg.AllowUntrustedBootstrap = "", "wstls", false, false
	cfg.RequireChannelAuth = p.RequireChannelAuth // the signed operator policy, never a previous operator's TOML flag
	cfg.CarrierSOCKS, cfg.CarrierTarget, cfg.Reality, cfg.InnerTLSPins = "", "", nil, nil
	cfg.SSHKey, cfg.SSHUser, cfg.SSHHostKeys, cfg.SSHDialHostOverride, cfg.SSHInternal, cfg.SSHClientVersion, cfg.SSHPort = "", "", "", "", "", "", ""
	cfg.FallbackSSH, cfg.HostileSSH, cfg.H3Tier, cfg.ECH = boolPtr(false), boolPtr(false), boolPtr(false), boolPtr(false)
}

func enrollPoolAtStartup(ctx context.Context, cfg *config.ClientConf, device *client.DeviceIdentity) error {
	// Pin this enrollment attempt to one node. A password is never retried
	// automatically to a changed node, another pool or an HTTP redirect.
	node := cfg.PoolNode()
	snapshot := *cfg
	snapshot.PoolNode = func() serverpool.Node { return node }
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := client.EnrollPool(setup, &snapshot, device, nil)
	cancel()
	if errors.Is(err, client.ErrEnrollmentDenied) {
		// A banned device must still reach the existing signed-status/ban
		// notice path. This exception never enrolls it or enables traffic.
		if status, _, _, _, statusErr := client.TokenStatus(&snapshot, device.Token); statusErr == nil && status == "banned" {
			return nil
		}
	}
	if !errors.Is(err, client.ErrEnrollmentLoginRequired) {
		return err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("verified pool requires enrollment login; restart in a terminal (passwords are not accepted through arguments, files or environment variables)")
	}
	fmt.Printf("Verified pool %s at %s requires enrollment login. This does not approve the device.\n", cfg.Pool.Name, node.Address)
	fmt.Print("Enrollment username: ")
	username, err := boundedConsoleLine()
	if err != nil {
		return err
	}
	fmt.Print("Enrollment password (hidden): ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	defer clear(password)
	if err != nil {
		return errors.New("could not read hidden enrollment password")
	}
	setup, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = client.EnrollPool(setup, &snapshot, device, &client.EnrollmentCredentials{Username: username, Password: password})
	if err != nil {
		return fmt.Errorf("enrollment login failed; no password saved or automatic retry: %w", err)
	}
	fmt.Println("Enrolled. A separate administrator approval is still required before traffic can pass.")
	return nil
}

func boundedConsoleLine() (string, error) {
	r := bufio.NewReaderSize(os.Stdin, 256)
	line, err := r.ReadSlice('\n')
	if err != nil && err != io.EOF {
		return "", errors.New("console input unavailable")
	}
	if len(line) > 256 {
		return "", errors.New("console input exceeds supported length")
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), nil
}
