package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"opentunnel/internal/client"
)

// Status is intentionally handled before crash logs, update/network recovery
// and identity creation. It is a private bounded summary, not a credential dump.
func handleStatusCommand(args []string) (bool, error) {
	has := false
	for _, arg := range args {
		if strings.TrimLeft(arg, "-") == "status" {
			has = true
		}
	}
	if !has {
		return false, nil
	}
	if len(args) != 1 || (args[0] != "--status" && args[0] != "-status") {
		return true, errors.New("--status is a standalone read-only command")
	}
	s, err := client.ReadRuntimeStatus()
	if os.IsNotExist(err) {
		fmt.Println("No local runtime status is recorded. This does not change or restore any network settings.")
		return true, nil
	}
	if err != nil {
		return true, err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return true, encoder.Encode(s)
}
