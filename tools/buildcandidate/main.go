// buildcandidate performs the fixed clean-source build recipe into a new local
// directory. It does not sign, execute artifacts, publish or authorize promotion.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/releasebuild"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "candidate build:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("buildcandidate", flag.ContinueOnError)
	dir := fs.String("directory", "", "new absolute local artifact directory outside source")
	source := fs.String("source-directory", "", "exact clean source checkout root")
	commit := fs.String("source-commit", "", "exact source HEAD SHA1")
	goExecutable := fs.String("go-executable", "", "absolute executable for the exact native Go toolchain; verified before artifact output")
	tag := fs.String("tag", "", "declared canonical candidate tag; never published by this tool")
	toolchain := fs.String("toolchain", "", "exact active Go version, including go prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !protocol.ValidReleaseTag(*tag) || *toolchain != runtime.Version() || !filepath.IsAbs(*dir) || filepath.Clean(*dir) != *dir || !filepath.IsAbs(*source) || filepath.Clean(*source) != *source {
		return errors.New("use exact toolchain, clean absolute source and new canonical absolute output")
	}
	relative, err := filepath.Rel(*source, *dir)
	if err != nil || relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return errors.New("candidate output cannot be within the source checkout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if !filepath.IsAbs(*goExecutable) || filepath.Clean(*goExecutable) != *goExecutable {
		return errors.New("supply the exact canonical absolute Go executable; trimmed builders have no embedded GOROOT")
	}
	if info, err := os.Lstat(*goExecutable); err != nil || !info.Mode().IsRegular() {
		return errors.New("explicit Go toolchain executable is linked or unavailable")
	}
	probe := exec.CommandContext(ctx, *goExecutable, "version")
	probe.Env = cleanBuildEnvironment(runtime.GOOS + "/" + runtime.GOARCH)
	versionOutput, err := probe.Output()
	if err != nil || string(versionOutput) != "go version "+*toolchain+" "+runtime.GOOS+"/"+runtime.GOARCH+"\n" {
		return errors.New("explicit native Go executable differs from the builder's exact toolchain")
	}
	if err := releasebuild.CheckFrozenSource(ctx, *source, *commit); err != nil {
		return err
	}
	if _, err := os.Lstat(*dir); !os.IsNotExist(err) {
		return errors.New("candidate output exists or is unavailable; preserve earlier builds")
	}
	if err := privatefile.EnsureDir(*dir); err != nil {
		return err
	}
	for _, target := range releasebuild.RecipeTargets() {
		arguments, err := releasebuild.BuildArguments(*tag, filepath.Join(*dir, target.Name), target)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, *goExecutable, arguments...)
		cmd.Dir = filepath.Join(*source, target.Directory)
		cmd.Env = cleanBuildEnvironment(target.Platform)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("fixed target %s failed; incomplete build evidence retained: %w", target.Name, err)
		}
		fmt.Println("Built", target.Name, "(unsigned; not release authorization)")
	}
	if err := releasebuild.CheckFrozenSource(ctx, *source, *commit); err != nil {
		return err
	}
	fmt.Println("Fixed recipe build complete. Independent reproduction, metadata validation, scoped signing and all release gates still required.")
	return nil
}

func cleanBuildEnvironment(platform string) []string {
	target := strings.Split(platform, "/")
	exclude := map[string]bool{"GOOS": true, "GOARCH": true, "CGO_ENABLED": true, "GOFLAGS": true, "GOENV": true, "GOEXPERIMENT": true, "GOFIPS140": true, "GOWORK": true, "GOTOOLCHAIN": true, "GOROOT": true, "GOTMPDIR": true, "GOAMD64": true, "GOARM64": true, "CC": true, "CXX": true, "CGO_CFLAGS": true, "CGO_CPPFLAGS": true, "CGO_CXXFLAGS": true, "CGO_LDFLAGS": true}
	var out []string
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !exclude[strings.ToUpper(key)] && !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			out = append(out, value)
		}
	}
	return append(out, "GOOS="+target[0], "GOARCH="+target[1], "CGO_ENABLED=0", "GOAMD64=v1", "GOARM64=v8.0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFIPS140=off")
}
