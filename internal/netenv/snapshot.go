package netenv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"opentunnel/internal/privatefile"
)

const journalSizeLimit = 256 << 10

func validJournalID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func importedJournalID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func validateRegistryValue(v registryValue) error {
	if !v.Exists {
		return nil
	}
	if v.Kind == 4 && v.Integer > 1<<32-1 {
		return errors.New("netenv: DWORD restoration would overflow")
	}
	switch v.Kind {
	case 1, 2, 3, 4, 7, 11:
		return nil
	default:
		return errors.New("netenv: invalid journal value type")
	}
}

func validateValueMap(path string, values map[string]registryValue) error {
	if path != regKeyPath && !policyPath(path) {
		return errors.New("netenv: journal names an unrelated registry key")
	}
	names := settingsNames(path)
	if len(values) != len(names) {
		return errors.New("netenv: incomplete settings bundle")
	}
	for _, name := range names {
		v, ok := values[name]
		if !ok {
			return errors.New("netenv: incomplete settings bundle")
		}
		if err := validateRegistryValue(v); err != nil {
			return err
		}
	}
	return nil
}

func validateJSONValueMap(raw json.RawMessage, path string) error {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return errors.New("netenv: incomplete registry-value dictionary")
	}
	for _, name := range settingsNames(path) {
		if err := requireJSONMembers(values[name], "exists"); err != nil {
			return err
		}
	}
	return nil
}

func validateTypedJSON(raw []byte, s snapshot) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, member := range []string{"values", "applied"} {
		if member == "applied" && fields[member] == nil && s.RecoveryOnly {
			continue // pre-address legacy recovery has no applied ownership
		}
		var paths map[string]json.RawMessage
		if err := json.Unmarshal(fields[member], &paths); err != nil {
			return err
		}
		for path, values := range paths {
			if err := validateJSONValueMap(values, path); err != nil {
				return err
			}
		}
	}
	for _, member := range []string{"had_keys", "touched"} {
		if member == "touched" && s.Version == 2 {
			continue // v2 never recorded attempted application
		}
		var paths map[string]json.RawMessage
		if err := json.Unmarshal(fields[member], &paths); err != nil {
			return err
		}
		for _, value := range paths {
			if strings.TrimSpace(string(value)) == "null" {
				return errors.New("netenv: unknown key existence/application state")
			}
		}
	}
	return nil
}

// Presence is separate from a known absent registry value. A null or omitted
// legacy member is not proof that the original was absent.
func requireJSONMembers(raw json.RawMessage, names ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return errors.New("netenv: incomplete journal object")
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || strings.TrimSpace(string(value)) == "null" {
			return fmt.Errorf("netenv: incomplete journal member %s", name)
		}
	}
	return nil
}

func validateLegacy(raw []byte, s snapshot) error {
	if err := requireJSONMembers(raw, "proxy_enable", "proxy_server", "proxy_override", "autoconfig_url"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, name := range []string{"proxy_server", "proxy_override", "autoconfig_url"} {
		if err := requireJSONMembers(fields[name], "exists"); err != nil {
			return err
		}
	}
	var policies map[string]json.RawMessage
	if err := json.Unmarshal(fields["policies"], &policies); err != nil && fields["policies"] != nil {
		return err
	}
	for path, policy := range policies {
		if !policyPath(path) {
			return errors.New("netenv: legacy journal names an unrelated policy key")
		}
		if err := requireJSONMembers(policy, "mode", "server", "bypass", "had_key"); err != nil {
			return err
		}
		var values map[string]json.RawMessage
		_ = json.Unmarshal(policy, &values)
		for _, name := range []string{"mode", "server", "bypass"} {
			if err := requireJSONMembers(values[name], "exists"); err != nil {
				return err
			}
		}
	}
	if s.Values != nil || s.Applied != nil || s.HadKeys != nil || s.Touched != nil || s.LegacyBypass != nil || s.RecoveryOnly {
		return errors.New("netenv: ambiguous legacy/typed journal")
	}
	return nil
}

func importLegacy(s *snapshot) {
	str := func(v stringVal) registryValue {
		if !v.Exists {
			return registryValue{}
		}
		return registryValue{Exists: true, Kind: 1, Text: v.Data}
	}
	s.Values = map[string]map[string]registryValue{regKeyPath: {
		"ProxyEnable": {Exists: true, Kind: 4, Integer: uint64(s.ProxyEnable)},
		"ProxyServer": str(s.ProxyServer), "ProxyOverride": str(s.ProxyOverride), "AutoConfigURL": str(s.AutoConfigURL),
	}}
	s.HadKeys = map[string]bool{regKeyPath: true}
	for path, v := range s.Policies {
		s.Values[path] = map[string]registryValue{polMode: str(v.Mode), polServer: str(v.Server), polBypass: str(v.Bypass)}
		s.HadKeys[path] = v.HadKey
	}
	s.Applied = make(map[string]map[string]registryValue)
	s.LegacyBypass = make(map[string]bool)
	if s.OtuAppliedServer != "" {
		intended := appliedSettings(s.OtuAppliedServer, nil)
		for path := range s.Values {
			s.Applied[path] = intended[path]
			s.LegacyBypass[path] = true
		}
		// Port v1.1.5's EXACT-address contaminated-original rule, only for
		// validated legacy journals. Do not infer contamination from ports,
		// loopback prefixes or arbitrary modern proxy settings. Conflict checks
		// still protect a replacement proxy when this cleaned original is used.
		if s.ProxyServer.Exists && s.ProxyServer.Data == s.OtuAppliedServer {
			s.Values[regKeyPath]["ProxyEnable"] = registryValue{Exists: true, Kind: 4, Integer: 0}
			s.Values[regKeyPath]["ProxyServer"] = registryValue{}
			s.Values[regKeyPath]["ProxyOverride"] = registryValue{}
		}
	}
	s.Touched = make(map[string]bool)
	for path := range s.Values {
		s.Touched[path] = true
	}
}

func readSnapshot(path string) (snapshot, error) {
	s := snapshot{}
	raw, err := privatefile.Read(path, journalSizeLimit)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("netenv: corrupt journal retained: %w", err)
	}
	if s.Owner.PID < 0 {
		return s, errors.New("netenv: invalid journal owner")
	}
	switch s.Version {
	case 0:
		if err := validateLegacy(raw, s); err != nil {
			return s, err
		}
		importLegacy(&s)
		s.ID = importedJournalID(raw)
		s.importRaw = raw
	case 2:
		if s.Owner.PID <= 0 || s.RecoveryOnly || s.LegacyBypass != nil {
			return s, errors.New("netenv: settings journal has no valid owner or migration state")
		}
		for _, path := range settingsPaths() {
			if _, ok := s.Values[path]; !ok {
				return s, errors.New("netenv: incomplete typed journal")
			}
		}
		s.ID = importedJournalID(raw)
		s.importRaw = raw
		s.Touched = make(map[string]bool)
		for path := range s.Values {
			s.Touched[path] = true // v2 recorded intent, not completed application
		}
	case 3:
		if !validJournalID(s.ID) || (s.Owner.PID <= 0 && !s.RecoveryOnly) {
			return s, errors.New("netenv: settings journal has no valid identity/owner")
		}
		if _, ok := s.Values[regKeyPath]; !ok {
			return s, errors.New("netenv: journal has no mandatory settings bundle")
		}
	default:
		return s, errors.New("netenv: unsupported journal version")
	}
	if s.Version != 0 {
		if err := validateTypedJSON(raw, s); err != nil {
			return s, err
		}
	}
	if len(s.Values) != len(s.HadKeys) || len(s.Values) != len(s.Touched) {
		return s, errors.New("netenv: incomplete key-existence/ownership journal")
	}
	for path, values := range s.Values {
		if err := validateValueMap(path, values); err != nil {
			return s, err
		}
		if _, ok := s.HadKeys[path]; !ok {
			return s, errors.New("netenv: incomplete key-existence journal")
		}
		if _, ok := s.Touched[path]; !ok {
			return s, errors.New("netenv: incomplete application-ownership journal")
		}
		if applied, ok := s.Applied[path]; ok {
			if err := validateValueMap(path, applied); err != nil {
				return s, err
			}
		} else if !s.RecoveryOnly && s.Version != 0 {
			return s, errors.New("netenv: incomplete applied-settings journal")
		}
	}
	for path := range s.Applied {
		if _, ok := s.Values[path]; !ok {
			return s, errors.New("netenv: applied journal names an uncaptured key")
		}
	}
	for path, unknown := range s.LegacyBypass {
		if _, ok := s.Values[path]; !ok || (unknown && s.Applied[path] == nil) || (s.Version == 3 && !s.RecoveryOnly) {
			return s, errors.New("netenv: invalid legacy bypass migration state")
		}
	}
	return s, nil
}
