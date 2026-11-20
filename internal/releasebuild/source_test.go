package releasebuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

type sourceTestEntry struct {
	Name string
	Data string
	Mode int64
	Kind byte
}

func syntheticSource(t *testing.T, extra ...sourceTestEntry) []byte {
	t.Helper()
	entries := []sourceTestEntry{{"go.mod", "module opentunnel\n\ngo 1.27.4\n", 0644, tar.TypeReg}, {"go.sum", "", 0644, tar.TypeReg}, {"LICENSE", "synthetic license fixture", 0644, tar.TypeReg}, {"cmd/otu-client/main.go", "package main\n", 0644, tar.TypeReg}, {"cmd/otu-server/main.go", "package main\n", 0644, tar.TypeReg}, {"cmd/otu-panel/main.go", "package main\n", 0644, tar.TypeReg}}
	entries = append(entries, extra...)
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: "opentunnel/" + entry.Name, Mode: entry.Mode, Size: int64(len(entry.Data)), Typeflag: entry.Kind, Format: tar.FormatUSTAR}
		if entry.Kind == tar.TypeSymlink {
			header.Linkname = "other"
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tw.Write([]byte(entry.Data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestSourceArchiveRejectsPrivateAliasedLinkedDuplicateAndTrailingPayloads(t *testing.T) {
	good := syntheticSource(t)
	if snapshot, err := ReadSourceArchive(good); err != nil || len(snapshot.Files) != 6 {
		t.Fatal("bounded source fixture rejected", err)
	}
	for _, entry := range []sourceTestEntry{
		{"../escape", "x", 0644, tar.TypeReg}, {"keys/operator", "x", 0644, tar.TypeReg}, {".git/config", "x", 0644, tar.TypeReg}, {"AGENTS.md", "x", 0644, tar.TypeReg},
		{"client-runtime/device.json", "x", 0644, tar.TypeReg}, {"file.", "x", 0644, tar.TypeReg}, {"go.mod", "x", 0644, tar.TypeReg}, {"GO.MOD", "x", 0644, tar.TypeReg},
		{"linked", "", 0644, tar.TypeSymlink}, {"privileged", "x", 04755, tar.TypeReg},
	} {
		if _, err := ReadSourceArchive(syntheticSource(t, entry)); err == nil {
			t.Fatal("unsafe source archive accepted", entry.Name)
		}
	}
	if _, err := ReadSourceArchive(append(bytes.Clone(good), good...)); err == nil {
		t.Fatal("multiple gzip streams accepted")
	}
	if _, err := ReadSourceArchive(append(bytes.Clone(good), []byte("hidden")...)); err == nil {
		t.Fatal("trailing compressed payload accepted")
	}
	bad := bytes.Clone(good)
	bad[len(bad)-8] ^= 1
	if _, err := ReadSourceArchive(bad); err == nil {
		t.Fatal("gzip checksum corruption accepted")
	}
}

func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(dir, "missing-global-config"))
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("synthetic Git fixture failed", err)
	}
	return strings.TrimSpace(string(raw))
}

func TestSourceRootComparisonUsesDirectoryIdentity(t *testing.T) {
	dir := t.TempDir()
	if !sourceRootMatches(filepath.Join(dir, "."), dir) || !sourceRootMatches(filepath.ToSlash(dir), dir) {
		t.Fatal("the same repository was rejected for an equivalent local path")
	}
	if sourceRootMatches(filepath.Dir(dir), dir) {
		t.Fatal("a parent directory was accepted as the repository root")
	}
	if runtime.GOOS == "windows" {
		msys := "/" + strings.ToLower(dir[:1]) + filepath.ToSlash(dir[2:])
		if !sourceRootMatches(msys, dir) {
			t.Fatal("Git for Windows MSYS drive spelling was rejected", msys)
		}
		root := filepath.VolumeName(dir) + `\`
		if !sourceRootMatches("/"+strings.ToLower(root[:1]), root) {
			t.Fatal("Git for Windows MSYS drive-root spelling was rejected")
		}
	}
}

func TestSourceRootComparisonRefusesLinkedCheckoutRoots(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	var links []string
	symlink := filepath.Join(base, "symlink")
	if err := os.Symlink(real, symlink); err == nil {
		links = append(links, symlink)
	} else if runtime.GOOS != "windows" {
		t.Fatal("could not create the synthetic directory symlink", err)
	}
	if runtime.GOOS == "windows" {
		junction := filepath.Join(base, "junction")
		if err := exec.Command("cmd", "/c", "mklink", "/J", junction, real).Run(); err == nil {
			links = append(links, junction)
		}
	}
	if len(links) == 0 {
		t.Skip("this machine cannot create a directory symlink or junction")
	}
	for _, link := range links {
		variants := []string{link, link + string(os.PathSeparator), filepath.Join(link, "."), filepath.ToSlash(link)}
		for _, requested := range variants {
			if sourceRootMatches(link, requested) {
				t.Fatalf("linked checkout root accepted: reported=%q requested=%q", link, requested)
			}
			if sourceRootMatches(requested, link) {
				t.Fatalf("linked checkout root accepted in requested position: reported=%q requested=%q", requested, link)
			}
		}
		if sourceRootMatches(real, link) || sourceRootMatches(link, real) {
			t.Fatalf("linked and real checkout roots compared equal: %q %q", link, real)
		}
	}
}

func TestSourceArchiveDeterministicGitObjectsNewOnlyAndDirtySourceRefusal(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is required for frozen source acceptance")
	}
	dir := t.TempDir()
	testGit(t, dir, "init", "--quiet")
	testGit(t, dir, "config", "core.autocrlf", "false")
	files := map[string]string{".gitignore": "hidden-build-input\n", "go.mod": "module opentunnel\n\ngo 1.27.4\n", "go.sum": "", "LICENSE": "synthetic", "cmd/otu-client/main.go": "package main\n", "cmd/otu-server/main.go": "package main\n", "cmd/otu-panel/main.go": "package main\n"}
	for name, data := range files {
		file := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	testGit(t, dir, "add", "--", ".")
	testGit(t, dir, "-c", "user.name=Synthetic Source Test", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "synthetic fixture")
	commit := testGit(t, dir, "rev-parse", "HEAD")
	first := filepath.Join(t.TempDir(), protocol.SourceArchiveName)
	second := filepath.Join(t.TempDir(), protocol.SourceArchiveName)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := WriteSourceArchive(ctx, dir, commit, first); err != nil {
		t.Fatal("first deterministic source archive failed", err)
	}
	if err := WriteSourceArchive(ctx, dir, commit, second); err != nil {
		t.Fatal("second deterministic source archive failed", err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same frozen Git objects did not produce identical archive bytes")
	}
	if err := WriteSourceArchive(ctx, dir, commit, first); err == nil {
		t.Fatal("source writer overwrote existing artifact")
	}
	snapshot, err := ReadSourceArchive(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceCheckout(ctx, snapshot, dir, commit); err != nil {
		t.Fatal(err)
	}
	// Git's normalized clean verdict must not hide different build bytes.
	testGit(t, dir, "update-index", "--assume-unchanged", "go.mod")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(strings.ReplaceAll(files["go.mod"], "\n", "\r\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFrozenSource(ctx, dir, commit); err == nil {
		t.Fatal("assume-unchanged/line-ending transformed source passed the exact build check")
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(files["go.mod"]), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, dir, "update-index", "--no-assume-unchanged", "go.mod")
	ignored := filepath.Join(dir, "hidden-build-input")
	if err := os.WriteFile(ignored, []byte("synthetic ignored embedding input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFrozenSource(ctx, dir, commit); err == nil {
		t.Fatal("ignored build input passed the exact frozen-source check")
	}
	if err := os.Remove(ignored); err != nil {
		t.Fatal(err) // only the extra ignored file created by this synthetic test
	}
	file := snapshot.Files["LICENSE"]
	file.SHA256 = strings.Repeat("a", 64)
	snapshot.Files["LICENSE"] = file
	if err := VerifySourceCheckout(ctx, snapshot, dir, commit); err == nil {
		t.Fatal("substituted source archive matched declared source commit")
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("modified user work"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSourceArchive(ctx, dir, commit, filepath.Join(t.TempDir(), protocol.SourceArchiveName)); err == nil {
		t.Fatal("dirty checkout accepted for source generation")
	}
}

func TestSourceModuleInventoryRejectsUnreviewedVersionsChecksumsAndReplacements(t *testing.T) {
	bundle := fixtureBundle()
	artifact := protocol.ReleaseArtifact{Name: "otu-server-linux-amd64", Platform: "linux/amd64"}
	info := fixtureBuildInfo(bundle, artifact)
	sum := "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	info.Deps = []*debug.Module{{Path: "example.invalid/module", Version: "v1.2.3", Sum: sum}}
	source := SourceSnapshot{Documents: map[string][]byte{"go.mod": []byte("module opentunnel\ngo 1.27.4\nrequire example.invalid/module v1.2.3\n"), "go.sum": []byte("example.invalid/module v1.2.3 " + sum + "\n")}}
	if err := verifyBinarySource(info, source, false, bundle.Toolchain); err != nil {
		t.Fatal(err)
	}
	info.Deps[0].Version = "v1.2.4"
	if err := verifyBinarySource(info, source, false, bundle.Toolchain); err == nil {
		t.Fatal("binary dependency substitution ignored")
	}
	for _, raw := range []string{"module opentunnel\ngo 1.27.4\nreplace example.invalid/module => ../local\n", "module opentunnel\ngo 1.27.4\nrequire (\nexample.invalid/module v1.2.3\nexample.invalid/module v1.2.3\n)\n"} {
		if _, err := readModuleRequirements([]byte(raw), nil); err == nil {
			t.Fatal("unreviewed source dependency directives accepted")
		}
	}
}

func TestBuildConsistencyDocumentCannotHideMissingOrNullArtifactMembers(t *testing.T) {
	bundle := fixtureBundle()
	bundle.Artifacts = []protocol.ReleaseArtifact{{Name: "otu-server-linux-amd64", Platform: "linux/amd64", SHA256: strings.Repeat("b", 64), Bytes: 1}, {Name: protocol.BuildProvenanceName, Platform: "metadata", SHA256: strings.Repeat("c", 64), Bytes: 1}}
	dir := t.TempDir()
	input := bundle
	input.Artifacts = bundle.Artifacts[:1]
	if err := WriteBuildDocument(dir, input); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, protocol.BuildProvenanceName))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBuildDocument(raw, bundle); err != nil {
		t.Fatal(err)
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	data["artifacts"] = json.RawMessage(`[{"name":"otu-server-linux-amd64","platform":"linux/amd64","sha256":"` + strings.Repeat("b", 64) + `"}]`)
	bad, _ := json.Marshal(data)
	if VerifyBuildDocument(bad, bundle) == nil {
		t.Fatal("omitted artifact byte count accepted")
	}
}

func TestArtifactSnapshotRefusesDeclaredSizeAndHashMismatch(t *testing.T) {
	data := []byte("synthetic executable bytes, never run")
	file := filepath.Join(t.TempDir(), "otu-client-windows-amd64.exe")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	a := protocol.ReleaseArtifact{Name: filepath.Base(file), Platform: "windows/amd64", Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	if got, err := ReadArtifact(file, a); err != nil || !bytes.Equal(got, data) {
		t.Fatal(err)
	}
	a.Bytes++
	if _, err := ReadArtifact(file, a); err == nil {
		t.Fatal("declared size ignored")
	}
	a.Bytes--
	a.SHA256 = strings.Repeat("a", 64)
	if _, err := ReadArtifact(file, a); err == nil {
		t.Fatal("payload digest ignored")
	}
}

func FuzzBoundedSourceArchive(f *testing.F) {
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = ReadSourceArchive(data)
	})
}
