package releasebuild

import (
	"bytes"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

func fixtureBundle() protocol.ReleaseBundle {
	now := time.Now()
	return protocol.ReleaseBundle{Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 1, RolloutPercent: 0, SourceCommit: strings.Repeat("a", 40), Toolchain: "go1.27.4", BuildRecipe: Recipe, MinimumVersion: "v1.1.10", RootVersion: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
}

func fixtureBuildInfo(bundle protocol.ReleaseBundle, artifact protocol.ReleaseArtifact) *debug.BuildInfo {
	path, module, tags, companion, _ := executableRole(artifact)
	flags, _ := LinkerFlags(bundle.Tag, companion)
	info := &debug.BuildInfo{GoVersion: bundle.Toolchain, Path: path, Main: debug.Module{Path: module, Version: "(devel)"}}
	if !companion {
		info.Main.Version = bundle.Tag
	}
	for key, value := range map[string]string{"GOOS": strings.Split(artifact.Platform, "/")[0], "GOARCH": strings.Split(artifact.Platform, "/")[1], "CGO_ENABLED": "0", "-buildmode": "exe", "-compiler": "gc", "-trimpath": "true", "-pgo": "off", "vcs": "git", "vcs.revision": bundle.SourceCommit, "vcs.modified": "false", "vcs.time": time.Unix(bundle.IssuedAt-60, 0).UTC().Format(time.RFC3339), "-ldflags": flags} {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: key, Value: value})
	}
	if strings.HasSuffix(artifact.Platform, "/amd64") {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: "GOAMD64", Value: "v1"})
	} else {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: "GOARM64", Value: "v8.0"})
	}
	if tags != "" {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: "-tags", Value: tags})
	}
	if companion {
		info.Deps = []*debug.Module{{Path: "github.com/xtls/xray-core", Version: XrayVersion, Sum: "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))}}
	}
	sort.Slice(info.Settings, func(i, j int) bool { return info.Settings[i].Key < info.Settings[j].Key })
	return info
}

func syntheticBuildSection(info *debug.BuildInfo) []byte {
	data := make([]byte, 32)
	copy(data, "\xff Go buildinf:")
	data[14], data[15] = 8, 2
	data = binary.AppendUvarint(data, uint64(len(info.GoVersion)))
	data = append(data, info.GoVersion...)
	module := strings.Repeat("S", 16) + info.String() + strings.Repeat("E", 16)
	data = binary.AppendUvarint(data, uint64(len(module)))
	return append(data, module...)
}

// These tiny containers are never executed. They cover format/metadata bounds,
// not build provenance or correct application behavior.
func syntheticExecutable(info *debug.BuildInfo, platform string) []byte {
	section := syntheticBuildSection(info)
	data := make([]byte, 1024+len(section))
	copy(data[1024:], section)
	if platform == "windows/amd64" {
		copy(data, "MZ")
		binary.LittleEndian.PutUint32(data[60:], 128)
		copy(data[128:], "PE\x00\x00")
		binary.LittleEndian.PutUint16(data[132:], 0x8664)
		binary.LittleEndian.PutUint16(data[134:], 2)
		binary.LittleEndian.PutUint16(data[148:], 240)
		binary.LittleEndian.PutUint16(data[150:], 2)
		binary.LittleEndian.PutUint16(data[152:], 0x20b)
		binary.LittleEndian.PutUint32(data[152+16:], 0x1000)
		binary.LittleEndian.PutUint64(data[152+24:], 0x140000000)
		table := data[392:]
		copy(table, ".text")
		binary.LittleEndian.PutUint32(table[8:], 32)
		binary.LittleEndian.PutUint32(table[12:], 0x1000)
		binary.LittleEndian.PutUint32(table[16:], 32)
		binary.LittleEndian.PutUint32(table[20:], 512)
		binary.LittleEndian.PutUint32(table[36:], 0x60000020)
		copy(table[40:], ".data")
		binary.LittleEndian.PutUint32(table[40+8:], uint32(len(section)))
		binary.LittleEndian.PutUint32(table[40+12:], 0x2000)
		binary.LittleEndian.PutUint32(table[40+16:], uint32(len(section)))
		binary.LittleEndian.PutUint32(table[40+20:], 1024)
		binary.LittleEndian.PutUint32(table[40+36:], 0xc0000040)
		return data
	}
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(data[16:], 2)
	machine := uint16(62)
	if platform == "linux/arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(data[18:], machine)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[24:], 0x400200)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint64(data[40:], 192)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint16(data[58:], 64)
	binary.LittleEndian.PutUint16(data[60:], 3)
	binary.LittleEndian.PutUint16(data[62:], 1)
	program := data[64:120]
	binary.LittleEndian.PutUint32(program, 1)
	binary.LittleEndian.PutUint32(program[4:], 7)
	binary.LittleEndian.PutUint64(program[16:], 0x400000)
	binary.LittleEndian.PutUint64(program[32:], uint64(len(data)))
	binary.LittleEndian.PutUint64(program[40:], uint64(len(data)))
	names := []byte("\x00.shstrtab\x00.go.buildinfo\x00")
	copy(data[512:], names)
	nameSection := data[192+64 : 192+128]
	binary.LittleEndian.PutUint32(nameSection, 1)
	binary.LittleEndian.PutUint32(nameSection[4:], 3)
	binary.LittleEndian.PutUint64(nameSection[24:], 512)
	binary.LittleEndian.PutUint64(nameSection[32:], uint64(len(names)))
	buildSection := data[192+128 : 192+192]
	binary.LittleEndian.PutUint32(buildSection, 11)
	binary.LittleEndian.PutUint32(buildSection[4:], 1)
	binary.LittleEndian.PutUint64(buildSection[8:], 3)
	binary.LittleEndian.PutUint64(buildSection[16:], 0x400400)
	binary.LittleEndian.PutUint64(buildSection[24:], 1024)
	binary.LittleEndian.PutUint64(buildSection[32:], uint64(len(section)))
	binary.LittleEndian.PutUint64(buildSection[48:], 16)
	return data
}

func TestExecutableRecipeBindsEveryCoreAndCompanionRoleAndEdition(t *testing.T) {
	bundle := fixtureBundle()
	for _, name := range []string{"otu-client-windows-amd64.exe", "otu-client-generic-windows-amd64.exe", "otu-client-linux-amd64", "otu-server-linux-amd64", "otu-panel-linux-arm64", "otu-xray-windows-amd64.exe"} {
		t.Run(name, func(t *testing.T) {
			platform, _, _ := protocol.ReleaseArtifactPolicy(name)
			artifact := protocol.ReleaseArtifact{Name: name, Platform: platform}
			info := fixtureBuildInfo(bundle, artifact)
			if err := ValidateBinaryInfo(info, bundle, artifact); err != nil {
				t.Fatal("exact synthetic recipe refused", err)
			}
			data := syntheticExecutable(info, platform)
			parsed, err := ReadBinaryInfo(data, artifact)
			if err != nil || ValidateBinaryInfo(parsed, bundle, artifact) != nil {
				t.Fatal("bounded synthetic container could not be parsed", err)
			}
			for _, key := range []string{"vcs.modified", "vcs.revision", "-pgo", "-ldflags", "CGO_ENABLED"} {
				bad := *info
				bad.Settings = append([]debug.BuildSetting(nil), info.Settings...)
				for i := range bad.Settings {
					if bad.Settings[i].Key == key {
						bad.Settings[i].Value = "unreviewed"
					}
				}
				if ValidateBinaryInfo(&bad, bundle, artifact) == nil {
					t.Fatal("artifact accepted a mismatched build declaration", key)
				}
			}
		})
	}
}

func TestExecutableParsingRejectsHugeTablesPointersMappingsAndStrings(t *testing.T) {
	bundle := fixtureBundle()
	for _, platform := range []string{"windows/amd64", "linux/amd64", "linux/arm64"} {
		artifact := protocol.ReleaseArtifact{Name: "otu-server-" + strings.ReplaceAll(platform, "/", "-"), Platform: platform}
		if platform == "windows/amd64" {
			artifact.Name += ".exe"
		}
		good := syntheticExecutable(fixtureBuildInfo(bundle, artifact), platform)
		mutations := []func([]byte){
			func(raw []byte) { raw[1024+15] = 0 },
			func(raw []byte) { raw[1024+16] = 1 },
			func(raw []byte) {
				for i := 1056; i < 1066; i++ {
					raw[i] = 0xff
				}
			},
		}
		if platform == "windows/amd64" {
			mutations = append(mutations,
				func(raw []byte) { binary.LittleEndian.PutUint32(raw[60:], ^uint32(0)) },
				func(raw []byte) { binary.LittleEndian.PutUint16(raw[134:], ^uint16(0)) },
				func(raw []byte) { binary.LittleEndian.PutUint32(raw[144:], 1<<30) },
				func(raw []byte) { binary.LittleEndian.PutUint32(raw[392+40+12:], 0x1000) },
			)
		} else {
			mutations = append(mutations,
				func(raw []byte) { binary.LittleEndian.PutUint16(raw[56:], ^uint16(0)) },
				func(raw []byte) { binary.LittleEndian.PutUint64(raw[40:], ^uint64(0)-10) },
				func(raw []byte) { binary.LittleEndian.PutUint64(raw[192+128+32:], MaxBuildInfoBytes+1) },
				func(raw []byte) { binary.LittleEndian.PutUint64(raw[192+128+24:], 512) },
			)
		}
		for i, mutate := range mutations {
			bad := bytes.Clone(good)
			mutate(bad)
			if _, err := ReadBinaryInfo(bad, artifact); err == nil {
				t.Fatal("malformed executable accepted", platform, i)
			}
		}
	}
}

func TestRealTrimpathMetadataAndPseudoVersionCannotImplyLinkerAuthorization(t *testing.T) {
	bundle := fixtureBundle()
	artifact := protocol.ReleaseArtifact{Name: "otu-client-windows-amd64.exe", Platform: "windows/amd64"}
	info := fixtureBuildInfo(bundle, artifact)
	var settings []debug.BuildSetting
	for _, setting := range info.Settings {
		if setting.Key != "-ldflags" && setting.Key != "-pgo" {
			settings = append(settings, setting)
		}
	}
	info.Settings = settings
	stamp := time.Unix(bundle.IssuedAt-60, 0).UTC().Format("20060102150405")
	info.Main.Version = "v1.1.11-0." + stamp + "-" + bundle.SourceCommit[:12]
	if err := ValidateBinaryInfo(info, bundle, artifact); err != nil {
		t.Fatal("real trimmed buildinfo contract rejected", err)
	}
	info.Main.Version = "v0.0.0-" + stamp + "-" + bundle.SourceCommit[:12]
	if err := ValidateBinaryInfo(info, bundle, artifact); err != nil {
		t.Fatal("untagged exact VCS pseudo-version rejected", err)
	}
	info.Main.Version = "v1.1.11-0." + stamp + "-bbbbbbbbbbbb"
	if err := ValidateBinaryInfo(info, bundle, artifact); err == nil {
		t.Fatal("pseudo-version from another source revision accepted")
	}
	info.Main.Version = bundle.Tag
	info.Settings = append(info.Settings, debug.BuildSetting{Key: "-ldflags", Value: "-X unreviewed=caller"})
	if err := ValidateBinaryInfo(info, bundle, artifact); err == nil {
		t.Fatal("present mismatched linker declaration was ignored")
	}
}

func TestBoundedBinaryReaderMatchesRealGoToolchainMetadata(t *testing.T) {
	// Read a separately built fixture, never execute it. The standard reader is
	// used only as this trusted-fixture oracle, not on untrusted release inputs.
	for _, env := range []string{"OTU_TEST_PRODUCTION_CLIENT_BINARY", "OTU_RELEASEBUILD_LINUX_BINARY", "OTU_RELEASEBUILD_ARM64_BINARY"} {
		file := os.Getenv(env)
		if file == "" {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		standard, err := buildinfo.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		platform := "windows/amd64"
		if env == "OTU_RELEASEBUILD_LINUX_BINARY" {
			platform = "linux/amd64"
		}
		if env == "OTU_RELEASEBUILD_ARM64_BINARY" {
			platform = "linux/arm64"
		}
		observed, err := ReadBinaryInfo(data, protocol.ReleaseArtifact{Platform: platform})
		if err != nil || !reflect.DeepEqual(standard, observed) {
			t.Fatal("bounded parser disagreed with trusted Go buildinfo", filepath.Base(file), err)
		}
	}
}

func FuzzBoundedBinaryInfo(f *testing.F) {
	f.Add([]byte("not an executable"), true)
	for _, platform := range []string{"linux/amd64", "windows/amd64"} {
		name := "otu-client-linux-amd64"
		if platform == "windows/amd64" {
			name = "otu-client-windows-amd64.exe"
		}
		artifact := protocol.ReleaseArtifact{Name: name, Platform: platform}
		f.Add(syntheticExecutable(fixtureBuildInfo(fixtureBundle(), artifact), platform), platform == "windows/amd64")
	}
	f.Fuzz(func(t *testing.T, data []byte, windows bool) {
		if len(data) > 1<<20 {
			return
		}
		platform := "linux/amd64"
		if windows {
			platform = "windows/amd64"
		}
		_, _ = ReadBinaryInfo(data, protocol.ReleaseArtifact{Platform: platform})
	})
}
