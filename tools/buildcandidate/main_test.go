package main

import (
	"strings"
	"testing"
)

func TestFixedBuildEnvironmentCannotInheritToolchainTagsExperimentOrCGOFlags(t *testing.T) {
	for _, name := range []string{"GOFLAGS", "GOENV", "GOEXPERIMENT", "CGO_CFLAGS", "CC", "GOARCH"} {
		t.Setenv(name, "SYNTHETIC_UNREVIEWED_SETTING")
	}
	for _, value := range cleanBuildEnvironment("linux/arm64") {
		if strings.Contains(value, "SYNTHETIC_UNREVIEWED_SETTING") {
			t.Fatal("build inherited an unreviewed flag/toolchain setting")
		}
	}
}
