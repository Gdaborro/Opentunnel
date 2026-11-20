package main

import (
	"strings"
	"testing"
)

func TestStopHelperUsesCheckedStopNotGlobalImageKill(t *testing.T) {
	contents, ok := stopHelperContents("otu client test.exe")
	if !ok {
		t.Fatal("safe executable name with spaces was refused")
	}
	if strings.Contains(contents, "taskkill") || strings.Contains(contents, "/IM") || !strings.Contains(contents, "--stop") {
		t.Fatal("helper does not use the checked owner stop", contents)
	}
	for _, name := range []string{"otu&whoami.exe", "otu%PATH%.exe", "otu^calc.exe", "otu\"calc.exe", "../otu.exe"} {
		if _, ok := stopHelperContents(name); ok {
			t.Fatal("unsafe batch image accepted", name)
		}
	}
}
