package releasebuild

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
)

const MaxSourceEntries = 20000
const MaxExpandedSourceBytes int64 = 512 << 20
const MaxSourceFileBytes int64 = 32 << 20

type SourceFile struct {
	Mode   int64
	Bytes  int64
	SHA256 string
}

type SourceSnapshot struct {
	Files     map[string]SourceFile
	Documents map[string][]byte // module/sum/license documents only, bounded
}

func sourcePathAllowed(name string) bool {
	if name == "" || len(name) > 240 || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\:\x00\r\n") || name == ".." || strings.HasPrefix(name, "../") {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if strings.TrimRight(component, " .") != component {
			return false
		}
		switch strings.ToLower(component) {
		case "keys", ".git", "otk", "agents.md", "device-identity", "client-runtime", "opentunnel-identity-reset-backups":
			return false
		}
	}
	return true
}

func sourceDocument(name string) bool {
	switch name {
	case "go.mod", "go.sum", "LICENSE", "companions/xray/go.mod", "companions/xray/go.sum", "companions/xray/README.md":
		return true
	default:
		return false
	}
}

func ReadSourceArchive(raw []byte) (SourceSnapshot, error) {
	snapshot := SourceSnapshot{Files: map[string]SourceFile{}, Documents: map[string][]byte{}}
	if len(raw) < 1 || len(raw) > 128<<20 {
		return snapshot, errors.New("source archive compressed byte bound exceeded")
	}
	input := bytes.NewReader(raw)
	gz, err := gzip.NewReader(input)
	if err != nil {
		return snapshot, errors.New("source archive is not gzip")
	}
	defer gz.Close()
	gz.Multistream(false)
	bounded := &io.LimitedReader{R: gz, N: MaxExpandedSourceBytes + 1}
	reader := tar.NewReader(bounded)
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header == nil || count >= MaxSourceEntries {
			return snapshot, errors.New("source archive malformed or too many entries")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "opentunnel" && header.Typeflag == tar.TypeDir && header.Size == 0 {
			if seen[name] || header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Mode&07000 != 0 {
				return snapshot, errors.New("source root has duplicate/link/extended attributes")
			}
			seen[name] = true
			continue
		}
		if !strings.HasPrefix(name, "opentunnel/") || header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Mode&07000 != 0 {
			return snapshot, errors.New("source archive has unsupported prefix/link/extended attributes")
		}
		name = strings.TrimPrefix(name, "opentunnel/")
		if !sourcePathAllowed(name) || seen[strings.ToLower(name)] {
			return snapshot, errors.New("private, aliased or duplicate source archive path")
		}
		seen[strings.ToLower(name)] = true
		if header.Typeflag == tar.TypeDir {
			if header.Size != 0 {
				return snapshot, errors.New("source directory has a payload")
			}
			continue
		}
		if (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || (header.Mode != 0644 && header.Mode != 0755) || header.Size < 0 || header.Size > MaxSourceFileBytes || header.Size > MaxExpandedSourceBytes-total {
			return snapshot, errors.New("source archive file type/mode/size unsupported")
		}
		total += header.Size
		hash := sha256.New()
		var n int64
		if sourceDocument(name) {
			maximum := int64(2 << 20)
			if strings.HasSuffix(name, "go.mod") {
				maximum = 64 << 10
			}
			if header.Size > maximum {
				return snapshot, errors.New("source module/license document exceeds bound")
			}
			data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
			if err != nil || int64(len(data)) != header.Size {
				return snapshot, errors.New("source document incomplete")
			}
			n = int64(len(data))
			_, _ = hash.Write(data)
			snapshot.Documents[name] = data
		} else {
			n, err = io.Copy(hash, reader)
			if err != nil || n != header.Size {
				return snapshot, errors.New("source file incomplete")
			}
		}
		snapshot.Files[name] = SourceFile{Mode: header.Mode, Bytes: n, SHA256: hex.EncodeToString(hash.Sum(nil))}
	}
	// Reading to checksum-verified EOF is mandatory. Multiple gzip streams or
	// nonzero hidden payload after the tar end cannot evade the source inventory.
	var buffer [8192]byte
	for {
		n, err := bounded.Read(buffer[:])
		if bounded.N <= 0 {
			return snapshot, errors.New("source archive expansion exceeds bound")
		}
		for _, value := range buffer[:n] {
			if value != 0 {
				return snapshot, errors.New("source archive has nonzero trailing tar payload")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return snapshot, errors.New("source gzip checksum or read failed")
		}
	}
	if input.Len() != 0 {
		return snapshot, errors.New("source archive has an extra gzip stream/trailing bytes")
	}
	for _, name := range []string{"go.mod", "go.sum", "LICENSE", "cmd/otu-client/main.go", "cmd/otu-server/main.go", "cmd/otu-panel/main.go"} {
		if _, exists := snapshot.Files[name]; !exists {
			return snapshot, errors.New("source archive missing a required core file")
		}
	}
	if !bytes.HasPrefix(snapshot.Documents["go.mod"], []byte("module opentunnel\n")) {
		return snapshot, errors.New("source archive main module differs")
	}
	return snapshot, nil
}

type boundedOutput struct {
	bytes.Buffer
	Maximum int
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	if len(raw) > b.Maximum-b.Len() {
		return 0, errors.New("Git source object/output exceeds bound")
	}
	return b.Buffer.Write(raw)
}

func gitOutput(ctx context.Context, dir string, maximum int, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"--no-replace-objects", "-C", dir}, args...)...)
	// A frozen object identity must not be redirected by an inherited worktree,
	// index, config injection or replacement reference. Git is still consistency
	// input, never independently authenticated signing/build authorization.
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	output := &boundedOutput{Maximum: maximum}
	cmd.Stdout, cmd.Stderr = output, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, errors.New("bounded Git source query failed")
	}
	return output.Bytes(), nil
}

type gitSourceFile struct {
	Name   string
	Object string
	Mode   int64
}

func sourceRootMatches(reportedRoot, requestedRoot string) bool {
	if reportedRoot == "" || requestedRoot == "" {
		return false
	}
	// Git for Windows can report the same directory with slash/drive/MSYS
	// spellings that filepath.Abs does not canonicalize identically. Compare
	// the actual directories, while refusing a linked checkout root.
	if runtime.GOOS == "windows" && len(reportedRoot) >= 2 && reportedRoot[0] == '/' {
		letter := reportedRoot[1]
		if (letter >= 'a' && letter <= 'z') || (letter >= 'A' && letter <= 'Z') {
			if len(reportedRoot) == 2 || reportedRoot[2] == '/' {
				remainder := ""
				if len(reportedRoot) > 2 {
					remainder = reportedRoot[3:]
				}
				reportedRoot = strings.ToUpper(reportedRoot[1:2]) + ":\\" + filepath.FromSlash(remainder)
			}
		}
	}
	for _, path := range []string{reportedRoot, requestedRoot} {
		// Normalize before inspecting the final component. Without Clean, a
		// trailing separator or "/." makes the OS resolve the last link during
		// traversal, so Lstat would inspect the target instead of the link.
		path = filepath.Clean(path)
		if !filepath.IsAbs(path) {
			return false
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	reported, err := os.Stat(filepath.Clean(reportedRoot))
	requested, err := os.Stat(filepath.Clean(requestedRoot))
	return err == nil && os.SameFile(reported, requested)
}

func frozenGitFiles(ctx context.Context, dir, commit string) ([]gitSourceFile, error) {
	if len(commit) != 40 {
		return nil, errors.New("exact Git source commit required")
	}
	if decoded, err := hex.DecodeString(commit); err != nil || len(decoded) != 20 || commit != strings.ToLower(commit) {
		return nil, errors.New("source commit is not canonical lowercase SHA1")
	}
	head, err := gitOutput(ctx, dir, 128, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != commit {
		return nil, errors.New("checkout HEAD differs from declared source commit")
	}
	status, err := gitOutput(ctx, dir, 1<<20, "status", "--porcelain", "--untracked-files=all")
	if err != nil || len(bytes.TrimSpace(status)) != 0 {
		return nil, errors.New("source checkout is not clean; frozen build refused")
	}
	// Ignored files can still affect Go embedding/build directives. A clean
	// status alone is not the complete build input: use a pristine checkout,
	// with generated assets committed and all output/caches kept outside it.
	ignored, err := gitOutput(ctx, dir, 1<<20, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
	if err != nil || len(ignored) != 0 {
		return nil, errors.New("source checkout contains ignored build inputs; use a pristine frozen checkout")
	}
	root, err := gitOutput(ctx, dir, 4096, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	actual := strings.TrimSpace(string(root))
	if err != nil || !sourceRootMatches(actual, dir) {
		return nil, errors.New("source directory must be the exact checkout root")
	}
	raw, err := gitOutput(ctx, dir, 8<<20, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	var files []gitSourceFile
	seen := map[string]bool{}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		metadata, name, ok := strings.Cut(string(entry), "\t")
		fields := strings.Fields(metadata)
		if !ok || len(fields) != 3 || fields[1] != "blob" || len(fields[2]) != 40 || !sourcePathAllowed(name) || seen[strings.ToLower(name)] || len(files) >= MaxSourceEntries {
			return nil, errors.New("Git tree has linked/submodule/aliased or unreviewed source entries")
		}
		mode := int64(0644)
		switch fields[0] {
		case "100644":
		case "100755":
			mode = 0755
		default:
			return nil, errors.New("Git tree contains a nonregular source entry")
		}
		seen[strings.ToLower(name)] = true
		files = append(files, gitSourceFile{Name: name, Object: fields[2], Mode: mode})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

func gitBlob(ctx context.Context, dir string, file gitSourceFile) ([]byte, error) {
	raw, err := gitOutput(ctx, dir, int(MaxSourceFileBytes), "cat-file", "blob", file.Object)
	if err != nil {
		return nil, err
	}
	hash := sha1.New()
	_, _ = fmt.Fprintf(hash, "blob %d\x00", len(raw))
	_, _ = hash.Write(raw)
	if hex.EncodeToString(hash.Sum(nil)) != file.Object {
		return nil, errors.New("Git source blob changed or does not match its object")
	}
	return raw, nil
}

func verifyWorktreeBlob(dir string, file gitSourceFile, expected []byte) error {
	// Git status applies clean filters and can hide CRLF/export transforms or
	// assume-unchanged files. Build source must match the archived Git bytes,
	// not merely look clean after those transformations.
	parts := strings.Split(file.Name, "/")
	parent := dir
	for _, component := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, component)
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("source checkout has a linked or missing ancestor")
		}
	}
	name := filepath.Join(dir, filepath.FromSlash(file.Name))
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() != int64(len(expected)) {
		return fmt.Errorf("source checkout bytes differ from Git at %s", file.Name)
	}
	f, err := os.Open(name)
	if err != nil {
		return errors.New("source checkout file cannot be opened")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return errors.New("source checkout file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || !bytes.Equal(raw, expected) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return fmt.Errorf("source checkout is not byte-identical to Git at %s; use a new unfiltered checkout", file.Name)
	}
	return nil
}

func VerifySourceCheckout(ctx context.Context, snapshot SourceSnapshot, dir, commit string) error {
	files, err := frozenGitFiles(ctx, dir, commit)
	if err != nil {
		return err
	}
	if len(files) != len(snapshot.Files) {
		return errors.New("source archive does not contain the exact frozen Git file set")
	}
	for _, file := range files {
		data, err := gitBlob(ctx, dir, file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if snapshot.Files[file.Name] != (SourceFile{Mode: file.Mode, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}) {
			return errors.New("source archive bytes/mode differ from frozen Git objects")
		}
		if err := verifyWorktreeBlob(dir, file, data); err != nil {
			return err
		}
	}
	_, err = frozenGitFiles(ctx, dir, commit) // refuse a concurrent checkout mutation
	return err
}

type moduleRequirements struct {
	Module       string
	Go           string
	Dependencies map[string]string
	Sums         map[string]string
}

func readModuleRequirements(mod, sums []byte) (moduleRequirements, error) {
	result := moduleRequirements{Dependencies: map[string]string{}, Sums: map[string]string{}}
	if len(mod) > 64<<10 || len(sums) > 2<<20 {
		return result, errors.New("source module requirement document exceeds bound")
	}
	group := false
	scanner := bufio.NewScanner(bytes.NewReader(mod))
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "//")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if group {
			if len(fields) == 1 && fields[0] == ")" {
				group = false
				continue
			}
			if len(fields) != 2 || result.Dependencies[fields[0]] != "" || !strings.HasPrefix(fields[1], "v") {
				return result, errors.New("unsupported or duplicate source module requirement")
			}
			result.Dependencies[fields[0]] = fields[1]
			continue
		}
		switch fields[0] {
		case "module":
			if len(fields) != 2 || result.Module != "" {
				return result, errors.New("invalid source main module")
			}
			result.Module = fields[1]
		case "go":
			if len(fields) != 2 || result.Go != "" {
				return result, errors.New("invalid source Go requirement")
			}
			result.Go = fields[1]
		case "require":
			if len(fields) == 2 && fields[1] == "(" {
				group = true
			} else if len(fields) == 3 && result.Dependencies[fields[1]] == "" && strings.HasPrefix(fields[2], "v") {
				result.Dependencies[fields[1]] = fields[2]
			} else {
				return result, errors.New("unsupported inline source module requirement")
			}
		default:
			return result, errors.New("unreviewed source module directive/replacement")
		}
	}
	if scanner.Err() != nil || group || result.Module == "" || result.Go == "" {
		return result, errors.New("source module requirement document malformed")
	}
	scanner = bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !validModuleSum(fields[2]) {
			return result, errors.New("source module sum line malformed")
		}
		key := fields[0] + " " + fields[1]
		if result.Sums[key] != "" {
			return result, errors.New("duplicate source module sum")
		}
		result.Sums[key] = fields[2]
	}
	if scanner.Err() != nil {
		return result, errors.New("source module sums cannot be read")
	}
	return result, nil
}

func sourceCommitTime(ctx context.Context, dir, commit string) (int64, error) {
	raw, err := gitOutput(ctx, dir, 128, "show", "-s", "--format=%ct", commit)
	if err != nil {
		return 0, err
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || epoch < 1 {
		return 0, errors.New("source commit timestamp is invalid")
	}
	return epoch, nil
}

type boundedWriter struct {
	Writer io.Writer
	Left   int64
}

func (w *boundedWriter) Write(raw []byte) (int, error) {
	if int64(len(raw)) > w.Left {
		return 0, errors.New("compressed source archive exceeds its output bound")
	}
	n, err := w.Writer.Write(raw)
	w.Left -= int64(n)
	return n, err
}

// WriteSourceArchive serializes only canonical regular Git blobs from the exact
// clean HEAD, with a deterministic USTAR/gzip recipe. It does not invoke git
// export filters, include untracked/ignored files, or treat Git as provenance.
func WriteSourceArchive(ctx context.Context, dir, commit, destination string) error {
	if err := CheckFrozenSource(ctx, dir, commit); err != nil {
		return err
	}
	files, err := frozenGitFiles(ctx, dir, commit)
	if err != nil {
		return err
	}
	epoch, err := sourceCommitTime(ctx, dir, commit)
	if err != nil {
		return err
	}
	if filepath.Base(destination) != protocol.SourceArchiveName || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return errors.New("source archive requires the fixed new absolute output name")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return errors.New("source archive output exists or is unavailable; preserve previous evidence")
	}
	if err := privatefile.EnsureDir(filepath.Dir(destination)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".source-archive-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary) // only the private temporary file this operation created
	if err := privatefile.Protect(temporary); err != nil {
		_ = f.Close()
		return err
	}
	gz, err := gzip.NewWriterLevel(&boundedWriter{Writer: f, Left: 128 << 20}, gzip.BestCompression)
	if err != nil {
		_ = f.Close()
		return err
	}
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	var total int64
	for _, file := range files {
		data, err := gitBlob(ctx, dir, file)
		if err != nil || int64(len(data)) > MaxExpandedSourceBytes-total {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return errors.Join(err, errors.New("source snapshot exceeds its bounded aggregate"))
		}
		total += int64(len(data))
		header := &tar.Header{Name: "opentunnel/" + file.Name, Typeflag: tar.TypeReg, Mode: file.Mode, Size: int64(len(data)), ModTime: time.Unix(epoch, 0).UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(header); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}
	}
	err = errors.Join(tw.Close(), gz.Close(), f.Sync(), f.Close())
	if err != nil {
		return err
	}
	raw, err := privatefile.ReadOnly(temporary, 128<<20)
	if err != nil {
		return err
	}
	snapshot, err := ReadSourceArchive(raw)
	if err != nil {
		return err
	}
	if err := VerifySourceCheckout(ctx, snapshot, dir, commit); err != nil {
		return err
	}
	return privatefile.WriteNew(destination, raw)
}
