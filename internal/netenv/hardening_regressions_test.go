package netenv

import (
	"os"
	"testing"
)

func TestValidatedLegacyContaminatedBrowserDoesNotRestoreDeadProxy(t *testing.T) {
	m, store := memoryManager(t)
	const dead = "127.0.0.1:18080"
	path := chromiumPolicyPaths[0]
	writeLegacy(t, m, snapshot{ProxyEnable: 1, ProxyServer: stringVal{Exists: true, Data: dead}, ProxyOverride: stringVal{Exists: true, Data: "localhost;127.0.0.1;<local>"},
		OtuAppliedServer: dead, Policies: map[string]policySnap{path: {Mode: stringVal{Exists: true, Data: "fixed_servers"}, Server: stringVal{Exists: true, Data: dead}, Bypass: stringVal{Exists: true, Data: "localhost,127.0.0.1,<local>"}, HadKey: true}}})
	store.keys[regKeyPath] = appliedSettings(dead, nil)[regKeyPath]
	store.keys[path] = appliedSettings(dead, nil)[path]
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if store.keys[path][polMode].Text == "fixed_servers" && store.keys[path][polServer].Text == dead {
		t.Fatal("recovery restored exact contaminated dead proxy")
	}
	if _, err := os.Stat(m.snapPath()); !os.IsNotExist(err) || m.PendingPolicyCleanup() {
		t.Fatal("completed cleanup retained active/pending state")
	}
}

func TestLegacyBrowserContaminationDoesNotGuessFromLoopbackPort(t *testing.T) {
	m, store := memoryManager(t)
	path := chromiumPolicyPaths[0]
	const ours = "127.0.0.1:18080"
	const other = "127.0.0.1:18081"
	writeLegacy(t, m, snapshot{ProxyServer: stringVal{}, ProxyOverride: stringVal{}, AutoConfigURL: stringVal{}, OtuAppliedServer: ours,
		Policies: map[string]policySnap{path: {Mode: stringVal{Exists: true, Data: "fixed_servers"}, Server: stringVal{Exists: true, Data: other}, Bypass: stringVal{}, HadKey: true}}})
	store.keys[regKeyPath] = appliedSettings(ours, nil)[regKeyPath]
	store.keys[path] = appliedSettings(ours, nil)[path]
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if store.keys[path][polServer].Text != other {
		t.Fatal("legitimate recorded loopback original was cleared")
	}
}
