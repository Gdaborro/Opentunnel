// otu-migrate is a local operator-only preparation tool. It never contacts a
// relay, reads raw signing credentials, installs binaries or restores a DB.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"opentunnel/internal/panel"
	"opentunnel/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "migration:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	fs := flag.NewFlagSet("otu-migrate", flag.ContinueOnError)
	dbPath := fs.String("database", "", "existing central/local panel database; never created implicitly")
	backup := fs.String("backup", "", "new private database backup path (required before enabling)")
	enable := fs.Bool("enable-channel-auth", false, "require v6 after all approved identities have channel canary evidence")
	pool := fs.String("confirm-pool", "", "exact operator pool ID")
	authority := fs.String("confirm-authority", "", "exact authority ID")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("opentunnel migration", version.Version)
		return nil
	}
	if fs.NArg() != 0 || *dbPath == "" {
		return fmt.Errorf("supply --database; default operation reports readiness without changing authentication policy")
	}
	info, err := os.Lstat(*dbPath)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("existing regular database required")
	}
	db, err := panel.Open(*dbPath, 14)
	if err != nil {
		return err
	}
	defer db.Close()
	report, err := db.ChannelMigrationReport(context.Background())
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if *backup != "" {
		destination, err := filepath.Abs(*backup)
		if err != nil {
			return err
		}
		if err := db.BackupDatabase(context.Background(), destination); err != nil {
			return err
		}
		fmt.Println("Verified private SQLite backup created; also preserve config/TLS/node inventory separately.")
	}
	if !*enable {
		return nil
	}
	if *backup == "" || *pool != report.PoolID || *authority != report.AuthorityID {
		return fmt.Errorf("enabling needs a new verified --backup and exact --confirm-pool/--confirm-authority")
	}
	if err := db.EnablePoolChannelAuthentication(context.Background(), *pool, *authority); err != nil {
		return err
	}
	fmt.Println("Stored policy migrated. Before restarting, explicitly set require_inner_tls=true and require_channel_auth=true on relay/panel configs. No live process or executable was changed.")
	return nil
}
