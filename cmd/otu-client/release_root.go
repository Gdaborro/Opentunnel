package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"opentunnel/internal/client"
	"opentunnel/internal/serverpool"
)

func handleReleaseRootCommand(args []string) (bool, error) {
	has := false
	for _, arg := range args {
		if strings.Split(strings.TrimLeft(arg, "-"), "=")[0] == "release-root-import" {
			has = true
		}
	}
	if !has {
		return false, nil
	}
	fs := flag.NewFlagSet("release root", flag.ContinueOnError)
	path := fs.String("release-root-import", "", "reviewed dual-threshold-signed root rotation file")
	confirm := fs.Bool("confirm-release-root", false, "explicitly authorize local release trust rotation, not fleet deployment")
	if err := fs.Parse(args); err != nil {
		return true, err
	}
	if fs.NArg() != 0 || *path == "" || !*confirm {
		return true, errors.New("root import needs --confirm-release-root and a reviewed public rotation file; no network/runtime flags")
	}
	raw, err := serverpool.ReadDocument(*path)
	if err != nil {
		return true, err
	}
	if err := client.ImportReleaseRoot(raw); err != nil {
		return true, err
	}
	fmt.Println("Verified old/new threshold signatures and stored the new release root. Device identity, operator trust and network settings were not changed.")
	return true, nil
}
