// pins.go: certificate pins learned in-band from the relay. The leaf
// changes at every Let's Encrypt renewal (~60-90 days); a fixed pin
// bricks every client at rotation. The relay announces its CURRENT leaf
// fingerprint on every control response — authenticated end to end by
// the device token, so a MITM cannot inject one — and the client journals
// it here, where it rejoins the dial pin set on every start.
package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// maxExtraPins bounds the learned-pin journal: rotation cadence needs two;
// eight tolerates years of renewals plus operational mistakes.
const maxExtraPins = 8

func extraPinPath() (string, error) {
	ts, err := NewTokenStore()
	if err != nil {
		return "", err
	}
	return filepath.Join(ts.Dir, "pins.json"), nil
}

// LoadExtraPins returns the pins learned in-band from the relay (possibly
// empty).
func LoadExtraPins() []string {
	path, err := extraPinPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s struct {
		Pins []string `json:"pins"`
	}
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	out := make([]string, 0, len(s.Pins))
	for _, p := range s.Pins {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SaveExtraPin records a pin announced by the relay (deduplicated,
// newest-kept ring).
func SaveExtraPin(fp string) {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return
	}
	pins := LoadExtraPins()
	for _, p := range pins {
		if strings.EqualFold(p, fp) {
			return
		}
	}
	path, err := extraPinPath()
	if err != nil {
		return
	}
	pins = append(pins, fp)
	if len(pins) > maxExtraPins {
		pins = pins[len(pins)-maxExtraPins:]
	}
	data, err := json.MarshalIndent(struct {
		Pins []string `json:"pins"`
	}{pins}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}
