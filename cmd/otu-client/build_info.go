package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"opentunnel/internal/config"
	"opentunnel/internal/version"
)

type clientBuildInfo struct {
	Version         string `json:"version"`
	Edition         string `json:"edition"`
	LocalPreview    string `json:"unreleased_local_preview,omitempty"`
	StateDirectory  string `json:"state_directory_name"`
	NetworkState    string `json:"network_state_directory_name"`
	WindowsAsset    string `json:"windows_update_asset"`
	OwnServerNeeded bool   `json:"own_server_configuration_required"`
}

// Read-only edition metadata is safe before identity/network/update recovery.
// It is a build declaration, not signed or reproducible-build authorization.
func handleBuildInfoCommand(args []string) (bool, error) {
	handled := false
	defaults := false
	for _, arg := range args {
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if name == "build-info" || name == "print-default-config" {
			handled = true
			defaults = name == "print-default-config"
		}
	}
	if !handled {
		return false, nil
	}
	if len(args) != 1 || (args[0] != "--build-info" && args[0] != "-build-info" && args[0] != "--print-default-config" && args[0] != "-print-default-config") {
		return true, errors.New("build/defaults queries are standalone; they cannot be mixed with runtime or recovery flags")
	}
	if defaults {
		fmt.Print(config.DefaultClientTOML)
		return true, nil
	}
	raw, err := json.Marshal(clientBuildInfo{Version: version.Version, Edition: version.ClientEdition, LocalPreview: version.LocalPreview, StateDirectory: version.ProductName, NetworkState: version.NetworkStateName(), WindowsAsset: version.ClientWindowsUpdateAsset, OwnServerNeeded: version.RequiresOwnServerConfiguration})
	if err != nil {
		return true, err
	}
	fmt.Println(string(raw))
	return true, nil
}
