package protocol

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"opentunnel/internal/serverpool"
)

// Release version comparison is checked and platform-independent. Overflowing
// components are invalid input, not an equal version or a disabled floor.
func releaseVersionParts(value string) ([3]uint64, error) {
	var parts [3]uint64
	if !releaseVersionPattern.MatchString(value) {
		return parts, errors.New("invalid canonical release tag")
	}
	for i, raw := range strings.Split(value[1:], ".") {
		component, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return parts, errors.New("release version component overflows")
		}
		parts[i] = component
	}
	return parts, nil
}

func ValidReleaseTag(value string) bool {
	_, err := releaseVersionParts(value)
	return err == nil
}

func CompareReleaseVersions(a, b string) (int, error) {
	left, err := releaseVersionParts(a)
	if err != nil {
		return 0, err
	}
	right, err := releaseVersionParts(b)
	if err != nil {
		return 0, err
	}
	for i := range left {
		if left[i] < right[i] {
			return -1, nil
		}
		if left[i] > right[i] {
			return 1, nil
		}
	}
	return 0, nil
}

// Strict JSON also needs presence validation: omitted false/zero fields must
// not acquire defaults in signed policy or persistent anti-rollback state.
func RequireJSONFields(raw []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return errors.New("JSON object required")
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || string(value) == "null" {
			return errors.New("required JSON member absent: " + name)
		}
	}
	return nil
}

func DecodeReleaseBundle(raw []byte) (ReleaseBundle, error) {
	var bundle ReleaseBundle
	if len(raw) > MaxBundleBytes || serverpool.DecodeStrict(raw, &bundle) != nil {
		return bundle, errors.New("release bundle schema invalid")
	}
	if err := RequireJSONFields(raw, "version", "tag", "channel", "sequence", "rollout_percent", "source_commit", "toolchain", "build_recipe", "minimum_version", "root_version", "issued_at", "expires_at", "artifacts"); err != nil {
		return bundle, err
	}
	var fields struct {
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return bundle, err
	}
	for _, artifact := range fields.Artifacts {
		if err := RequireJSONFields(artifact, "name", "platform", "sha256", "bytes"); err != nil {
			return bundle, err
		}
	}
	return bundle, nil
}
