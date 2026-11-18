// Package releasebuild checks release payload consistency. Declared metadata,
// Git objects and buildinfo are NOT independently authenticated build evidence;
// these checks must never authorize signing keys, deployment or gate waivers.
package releasebuild

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"opentunnel/internal/protocol"
)

const Recipe = "otu-repro-v1"
const MaxBuildInfoBytes = 256 << 10
const XrayVersion = "v1.260327.1-0.20261109052709-676eaf66f8f0"

var sourcePseudoVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-(?:[0-9A-Za-z.-]+\.)?([0-9]{14})-([0-9a-f]{12})$`)

func LinkerFlags(tag string, companion bool) (string, error) {
	if !protocol.ValidReleaseTag(tag) {
		return "", errors.New("canonical release tag required for the build recipe")
	}
	flags := "-s -w -buildid="
	if !companion {
		flags += " -X opentunnel/internal/version.Version=" + tag +
			" -X opentunnel/internal/client.MinUpdateTag=" + tag +
			" -X opentunnel/internal/client.ReleaseBundleFloor=" + tag
	}
	return flags, nil
}

func executableRole(artifact protocol.ReleaseArtifact) (path, module, tags string, companion bool, err error) {
	platform, _, allowed := protocol.ReleaseArtifactPolicy(artifact.Name)
	if !allowed || platform != artifact.Platform || !strings.Contains(platform, "/") {
		return "", "", "", false, errors.New("unsupported executable name/platform role")
	}
	if artifact.Name == "otu-client-generic-windows-amd64.exe" {
		return "opentunnel/cmd/otu-client", "opentunnel", "genericclient", false, nil
	}
	for _, product := range []string{"client", "server", "panel", "pool", "migrate", "reality", "xray"} {
		if !strings.HasPrefix(artifact.Name, "otu-"+product+"-") {
			continue
		}
		if product == "xray" {
			return "opentunnel-xray-companion", "opentunnel-xray-companion", "", true, nil
		}
		if product == "client" && strings.HasPrefix(platform, "linux/") {
			tags = "genericclient"
		}
		return "opentunnel/cmd/otu-" + product, "opentunnel", tags, false, nil
	}
	return "", "", "", false, errors.New("executable role has no reviewed package")
}

// ReadArtifact hashes and parses exactly one bounded ordinary-file snapshot.
// Its bytes are reused by all consistency checks; no reopen can silently verify
// a different payload. Cross-file immutability is a separate release ceremony.
func ReadArtifact(path string, artifact protocol.ReleaseArtifact) ([]byte, error) {
	platform, limit, allowed := protocol.ReleaseArtifactPolicy(artifact.Name)
	if !allowed || platform != artifact.Platform || artifact.Bytes < 1 || artifact.Bytes > limit {
		return nil, errors.New("artifact name/platform/size is outside the release contract")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() != artifact.Bytes {
		return nil, errors.New("release artifact is linked, missing or differs from declared size")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("release artifact changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, artifact.Bytes+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != artifact.Bytes || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("release artifact changed during bounded snapshot")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != artifact.SHA256 {
		return nil, errors.New("release artifact differs from the signed inventory hash")
	}
	return raw, nil
}

func sectionRange(raw []byte, offset, length uint64) ([]byte, error) {
	if offset > uint64(len(raw)) || length > uint64(len(raw))-offset {
		return nil, errors.New("executable section range escapes the bounded payload")
	}
	return raw[offset : offset+length], nil
}

func inlineBuildInfo(section []byte, address uint64) (*debug.BuildInfo, error) {
	magic := []byte("\xff Go buildinf:")
	for offset := int((16 - address%16) % 16); offset+32 <= len(section) && offset < 64<<10; offset += 16 {
		if !bytes.Equal(section[offset:offset+len(magic)], magic) {
			continue
		}
		header := section[offset : offset+32]
		if header[14] != 8 || header[15] != 2 || !bytes.Equal(header[16:], make([]byte, 16)) {
			return nil, errors.New("executable uses an unsupported indirect/legacy buildinfo layout")
		}
		body := section[offset+32:]
		var values [2]string
		for i, maximum := range []uint64{64, MaxBuildInfoBytes} {
			length, n := binary.Uvarint(body)
			if n <= 0 || length < 1 || length > maximum || uint64(len(body)-n) < length {
				return nil, errors.New("executable buildinfo string exceeds its bounded layout")
			}
			values[i] = string(body[n : n+int(length)])
			body = body[n+int(length):]
		}
		// Go module framing matches runtime/debug and the standard buildinfo
		// reader. Parsing these already-bounded strings avoids generic PE/ELF
		// readers allocating from attacker-controlled virtual section sizes.
		module := values[1]
		if len(module) < 33 || module[len(module)-17] != '\n' {
			return nil, errors.New("executable module-info framing is malformed")
		}
		info, err := debug.ParseBuildInfo(module[16 : len(module)-16])
		if err != nil {
			return nil, errors.New("bounded executable module-info cannot be parsed")
		}
		info.GoVersion = values[0]
		return info, nil
	}
	return nil, errors.New("bounded executable Go buildinfo section is missing")
}

func ReadBinaryInfo(raw []byte, artifact protocol.ReleaseArtifact) (info *debug.BuildInfo, retErr error) {
	defer func() {
		if recover() != nil {
			info, retErr = nil, errors.New("malformed executable consistency input")
		}
	}()
	if len(raw) < 128 || len(raw) > 64<<20 {
		return nil, errors.New("executable payload is outside its byte bound")
	}
	if artifact.Platform == "windows/amd64" {
		if !bytes.HasPrefix(raw, []byte("MZ")) {
			return nil, errors.New("Windows executable is not PE")
		}
		offset := uint64(binary.LittleEndian.Uint32(raw[60:64]))
		header, err := sectionRange(raw, offset, 24)
		if err != nil || offset < 64 || offset > 4096 || !bytes.Equal(header[:4], []byte("PE\x00\x00")) || binary.LittleEndian.Uint16(header[4:6]) != 0x8664 {
			return nil, errors.New("PE header/machine differs from windows/amd64")
		}
		sections := uint64(binary.LittleEndian.Uint16(header[6:8]))
		optional := uint64(binary.LittleEndian.Uint16(header[20:22]))
		if sections < 1 || sections > 64 || optional != 240 || binary.LittleEndian.Uint32(header[16:20]) != 0 || binary.LittleEndian.Uint16(header[22:24])&0x2002 != 2 {
			return nil, errors.New("PE table count/header bound exceeded")
		}
		// Go's stripped PE emits zero COFF symbols but may retain a pointer
		// to its four-byte empty string table. Accept exactly that bounded
		// layout, not arbitrary symbol counts or virtual allocations.
		if symbols := uint64(binary.LittleEndian.Uint32(header[12:16])); symbols != 0 {
			strings, err := sectionRange(raw, symbols, 4)
			if err != nil || binary.LittleEndian.Uint32(strings) != 4 {
				return nil, errors.New("PE empty symbol/string table is malformed")
			}
		}
		optionalHeader, err := sectionRange(raw, offset+24, optional)
		if err != nil || binary.LittleEndian.Uint16(optionalHeader[:2]) != 0x20b {
			return nil, errors.New("unsupported PE optional header")
		}
		imageBase := binary.LittleEndian.Uint64(optionalHeader[24:32])
		entry := uint64(binary.LittleEndian.Uint32(optionalHeader[16:20]))
		table, err := sectionRange(raw, offset+24+optional, sections*40)
		if err != nil {
			return nil, err
		}
		var buildSection []byte
		var buildAddress uint64
		var ranges [][2]uint64
		entryFound := false
		for i := uint64(0); i < sections; i++ {
			section := table[i*40 : (i+1)*40]
			virtualSize := uint64(binary.LittleEndian.Uint32(section[8:12]))
			address := uint64(binary.LittleEndian.Uint32(section[12:16]))
			size := uint64(binary.LittleEndian.Uint32(section[16:20]))
			fileOffset := uint64(binary.LittleEndian.Uint32(section[20:24]))
			flags := binary.LittleEndian.Uint32(section[36:40])
			if address+size > 1<<32 || virtualSize > 256<<20 || address+virtualSize > 1<<32 || imageBase > ^uint64(0)-address {
				return nil, errors.New("PE virtual section range exceeds bounds")
			}
			payload, err := sectionRange(raw, fileOffset, size)
			if err != nil {
				return nil, err
			}
			if size > 0 {
				for _, earlier := range ranges {
					if address < earlier[1] && earlier[0] < address+size {
						return nil, errors.New("ambiguous overlapping PE virtual sections")
					}
				}
				ranges = append(ranges, [2]uint64{address, address + size})
			}
			entryFound = entryFound || (entry != 0 && entry >= address && entry-address < size && flags&0x20000020 == 0x20000020)
			// Match Go's first initialized writable data section, not an
			// attacker-chosen later named section containing alternate metadata.
			if buildSection == nil && address > 0 && size > 0 && flags&^uint32(0x600000) == 0xc0000040 {
				buildSection = payload[:min(size, virtualSize)]
				buildAddress = imageBase + address
			}
		}
		if !entryFound || buildSection == nil {
			return nil, errors.New("PE lacks code entry or bounded Go buildinfo data")
		}
		return inlineBuildInfo(buildSection, buildAddress)
	} else if artifact.Platform == "linux/amd64" || artifact.Platform == "linux/arm64" {
		if !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) || raw[4] != 2 || raw[5] != 1 || raw[6] != 1 || binary.LittleEndian.Uint16(raw[16:18]) != 2 || binary.LittleEndian.Uint32(raw[20:24]) != 1 || binary.LittleEndian.Uint16(raw[52:54]) != 64 {
			return nil, errors.New("Linux executable is not reviewed little-endian ELF64")
		}
		machine := uint16(62)
		if artifact.Platform == "linux/arm64" {
			machine = 183
		}
		if binary.LittleEndian.Uint16(raw[18:20]) != machine {
			return nil, errors.New("ELF machine differs from artifact platform")
		}
		programs, sections := uint64(binary.LittleEndian.Uint16(raw[56:58])), uint64(binary.LittleEndian.Uint16(raw[60:62]))
		nameIndex := uint64(binary.LittleEndian.Uint16(raw[62:64]))
		if programs < 1 || programs > 32 || sections < 1 || sections > 128 || nameIndex < 1 || nameIndex >= sections || binary.LittleEndian.Uint16(raw[58:60]) != 64 || binary.LittleEndian.Uint16(raw[54:56]) != 56 {
			return nil, errors.New("ELF table count/header bound exceeded")
		}
		programTable, err := sectionRange(raw, binary.LittleEndian.Uint64(raw[32:40]), programs*56)
		if err != nil {
			return nil, err
		}
		sectionTable, err := sectionRange(raw, binary.LittleEndian.Uint64(raw[40:48]), sections*64)
		if err != nil {
			return nil, err
		}
		entry := binary.LittleEndian.Uint64(raw[24:32])
		entryFound := false
		for i := uint64(0); i < programs; i++ {
			program := programTable[i*56 : (i+1)*56]
			size, memory := binary.LittleEndian.Uint64(program[32:40]), binary.LittleEndian.Uint64(program[40:48])
			address := binary.LittleEndian.Uint64(program[16:24])
			if size > memory || memory > 256<<20 || address > ^uint64(0)-memory {
				return nil, errors.New("ELF segment virtual size exceeds bounds")
			}
			if _, err := sectionRange(raw, binary.LittleEndian.Uint64(program[8:16]), size); err != nil {
				return nil, err
			}
			entryFound = entryFound || (binary.LittleEndian.Uint32(program[:4]) == 1 && binary.LittleEndian.Uint32(program[4:8])&1 != 0 && entry != 0 && entry >= address && entry-address < size)
		}
		nameSection := sectionTable[nameIndex*64 : (nameIndex+1)*64]
		nameSize := binary.LittleEndian.Uint64(nameSection[32:40])
		if binary.LittleEndian.Uint32(nameSection[4:8]) != 3 || nameSize > 64<<10 {
			return nil, errors.New("ELF section-name table exceeds bounds")
		}
		names, err := sectionRange(raw, binary.LittleEndian.Uint64(nameSection[24:32]), nameSize)
		if err != nil {
			return nil, err
		}
		var buildSection []byte
		var buildAddress uint64
		for i := uint64(0); i < sections; i++ {
			section := sectionTable[i*64 : (i+1)*64]
			nameOffset := uint64(binary.LittleEndian.Uint32(section[:4]))
			if nameOffset >= uint64(len(names)) || binary.LittleEndian.Uint64(section[8:16])&0x800 != 0 {
				return nil, errors.New("ELF section names/compression unsupported")
			}
			end := bytes.IndexByte(names[nameOffset:], 0)
			if end < 0 || end > 128 {
				return nil, errors.New("ELF section name exceeds bounds")
			}
			size, fileOffset, address := binary.LittleEndian.Uint64(section[32:40]), binary.LittleEndian.Uint64(section[24:32]), binary.LittleEndian.Uint64(section[16:24])
			kind := binary.LittleEndian.Uint32(section[4:8])
			if size > 256<<20 || address > ^uint64(0)-size {
				return nil, errors.New("ELF virtual section range exceeds bounds")
			}
			if kind != 8 {
				if _, err := sectionRange(raw, fileOffset, size); err != nil {
					return nil, err
				}
			}
			if string(names[nameOffset:nameOffset+uint64(end)]) != ".go.buildinfo" {
				continue
			}
			if buildSection != nil || kind != 1 || size < 32 || size > MaxBuildInfoBytes {
				return nil, errors.New("duplicate or oversized ELF Go buildinfo section")
			}
			mapped := false
			for j := uint64(0); j < programs; j++ {
				program := programTable[j*56 : (j+1)*56]
				base, extent := binary.LittleEndian.Uint64(program[16:24]), binary.LittleEndian.Uint64(program[32:40])
				if address < base || address-base >= extent {
					continue
				}
				if binary.LittleEndian.Uint32(program[:4]) != 1 || size > extent-(address-base) || fileOffset != binary.LittleEndian.Uint64(program[8:16])+(address-base) {
					return nil, errors.New("ELF Go buildinfo differs from its first mapped data segment")
				}
				mapped = true
				break
			}
			if !mapped {
				return nil, errors.New("ELF Go buildinfo has no file-backed data segment")
			}
			buildSection, _ = sectionRange(raw, fileOffset, size)
			buildAddress = address
		}
		if !entryFound || buildSection == nil {
			return nil, errors.New("ELF lacks code entry or bounded Go buildinfo data")
		}
		return inlineBuildInfo(buildSection, buildAddress)
	} else {
		return nil, errors.New("artifact is not an executable platform")
	}
}

func validModuleSum(value string) bool {
	if !strings.HasPrefix(value, "h1:") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(value[3:])
	return err == nil && len(raw) == sha256.Size && "h1:"+base64.StdEncoding.EncodeToString(raw) == value
}

func ValidateBinaryInfo(info *debug.BuildInfo, bundle protocol.ReleaseBundle, artifact protocol.ReleaseArtifact) error {
	if !protocol.ValidReleaseTag(bundle.Tag) || len(bundle.SourceCommit) != 40 {
		return errors.New("binary consistency requires checked tag/source identifiers")
	}
	if raw, err := hex.DecodeString(bundle.SourceCommit); err != nil || len(raw) != 20 || bundle.SourceCommit != strings.ToLower(bundle.SourceCommit) {
		return errors.New("binary consistency source commit is not canonical SHA1")
	}
	path, module, tags, companion, err := executableRole(artifact)
	if err != nil {
		return err
	}
	if bundle.BuildRecipe != Recipe || info == nil || info.Path != path || info.GoVersion != bundle.Toolchain || info.Main.Path != module || info.Main.Replace != nil || info.Main.Sum != "" || len(info.Deps) > 1024 || len(info.Settings) > 64 {
		return errors.New("executable package/module/toolchain differs from the build recipe")
	}
	seen := map[string]bool{module: true}
	foundXray := false
	for _, dependency := range info.Deps {
		if dependency == nil || dependency.Replace != nil || dependency.Path == "" || seen[dependency.Path] || len(dependency.Path) > 256 || len(dependency.Version) > 128 || !strings.HasPrefix(dependency.Version, "v") || strings.ContainsAny(dependency.Path+dependency.Version, " \t\r\n\\") || !validModuleSum(dependency.Sum) {
			return errors.New("unreviewed replacement/duplicate or malformed dependency buildinfo")
		}
		seen[dependency.Path] = true
		if dependency.Path == "github.com/xtls/xray-core" {
			foundXray = dependency.Version == XrayVersion
		}
	}
	if companion && !foundXray {
		return errors.New("restricted companion does not bind its reviewed upstream Xray version")
	}
	target := strings.Split(artifact.Platform, "/")
	required := map[string]string{"GOOS": target[0], "GOARCH": target[1], "CGO_ENABLED": "0", "-buildmode": "exe", "-compiler": "gc", "-trimpath": "true", "vcs": "git", "vcs.revision": bundle.SourceCommit, "vcs.modified": "false"}
	if target[1] == "amd64" {
		required["GOAMD64"] = "v1"
	} else {
		required["GOARM64"] = "v8.0"
	}
	if tags != "" {
		required["-tags"] = tags
	}
	flags, err := LinkerFlags(bundle.Tag, companion)
	if err != nil {
		return err
	}
	// Go omits -ldflags under -trimpath (go.dev/issue/52372) and records
	// no -pgo setting when it is off. Missing values are not authenticated
	// proof of the linker/PGO recipe: exact independent reproduction remains
	// mandatory. If these declarations are present, they must match exactly.
	optional := map[string]string{"-tags": "", "-ldflags": flags, "-pgo": "off", "GOEXPERIMENT": "", "GOFIPS140": "off", "DefaultGODEBUG": ""}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate || len(setting.Key) > 64 || len(setting.Value) > 4096 {
			return errors.New("duplicate or oversized executable build setting")
		}
		settings[setting.Key] = setting.Value
		if expected, ok := required[setting.Key]; ok {
			if setting.Value != expected {
				return fmt.Errorf("executable recipe differs at %s", setting.Key)
			}
		} else if expected, ok := optional[setting.Key]; ok {
			if setting.Value != expected {
				return errors.New("unreviewed optional executable build setting")
			}
		} else if setting.Key != "vcs.time" {
			return errors.New("unreviewed executable build setting")
		}
	}
	for name := range required {
		if _, ok := settings[name]; !ok {
			return fmt.Errorf("executable recipe is missing %s", name)
		}
	}
	committed, err := time.Parse(time.RFC3339, settings["vcs.time"])
	if err != nil || committed.Unix() <= 0 || committed.Unix() > bundle.IssuedAt {
		return errors.New("executable VCS timestamp is inconsistent with bundle issuance")
	}
	if companion {
		if info.Main.Version != "(devel)" {
			return errors.New("companion main module must use its reviewed untagged wrapper identity")
		}
	} else if info.Main.Version != bundle.Tag {
		parts := sourcePseudoVersion.FindStringSubmatch(info.Main.Version)
		if len(parts) != 3 || parts[1] != committed.UTC().Format("20060102150405") || parts[2] != bundle.SourceCommit[:12] {
			return errors.New("main module version is not the tagged target or its exact VCS-bound pseudo-version")
		}
	}
	return nil
}
