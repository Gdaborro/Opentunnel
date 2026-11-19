package main

import "testing"

func TestNetworkRecoveryRequestedUsesParsedSemantics(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--restore"}, true},
		{[]string{"-restore"}, true},
		{[]string{"--restore=true"}, true},
		{[]string{"--restore=false"}, false},
		{[]string{"--restore=0"}, false},
		{[]string{"--restore-from"}, false},
		{[]string{"--restore-from", "backup.json"}, true},
		{[]string{"--restore-from=backup.json"}, true},
		{[]string{"--restore-from="}, false},
		{[]string{"-c", "--restore"}, false},
		{[]string{"-c=--restore"}, false},
		{[]string{"--qr", "--restore"}, false},
		{[]string{"--", "--restore"}, false},
		{[]string{"--restore-from", "--restore"}, true}, // restore-from's value, however invalid
		{[]string{"run", "--restore=false"}, false},
		{[]string{"--stop"}, true},
	} {
		if got := networkRecoveryRequested(tc.args); got != tc.want {
			t.Errorf("networkRecoveryRequested(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
