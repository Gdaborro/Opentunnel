package client

import (
	"net/http"
	"sync"

	"opentunnel/internal/config"
	"opentunnel/internal/transport"
)

var carrierControl struct {
	sync.Mutex
	cfg     *config.ClientConf
	options transport.CarrierOptions
}

// InstallCarrierControl shares the supervisor's private local SOCKS auth with
// bootstrap/control requests without persisting it in the user's TOML file.
// Installation belongs to one runtime/config and is removed on shutdown.
func InstallCarrierControl(cfg *config.ClientConf, options transport.CarrierOptions) func() {
	carrierControl.Lock()
	carrierControl.cfg = cfg
	carrierControl.options = options
	carrierControl.Unlock()
	return func() {
		carrierControl.Lock()
		if carrierControl.cfg == cfg {
			carrierControl.cfg = nil
			carrierControl.options = transport.CarrierOptions{}
		}
		carrierControl.Unlock()
	}
}

func carrierHTTP(cfg *config.ClientConf) (*http.Client, string, error) {
	options := transport.CarrierOptions{SOCKSAddr: cfg.CarrierSOCKS, Target: cfg.CarrierTarget}
	carrierControl.Lock()
	if carrierControl.cfg == cfg {
		options = carrierControl.options
	}
	carrierControl.Unlock()
	cl, err := transport.NewCarrierHTTPClient(options)
	return cl, "http://" + options.Target, err
}
