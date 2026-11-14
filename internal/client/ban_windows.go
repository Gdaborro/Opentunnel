//go:build windows && !netenvfixture

package client

import (
	"crypto/sha256"
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

func deviceFingerprint() string {
	guid := ""
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err == nil {
		guid, _, _ = k.GetStringValue("MachineGuid")
		k.Close()
	}
	hostname, _ := os.Hostname()
	raw := fmt.Sprintf("%s|%s", guid, hostname)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:16])
}

var banState banBackend = windowsBanBackend{}

type windowsBanBackend struct{}

func (windowsBanBackend) Banned() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\OpenTunnel`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("BanReason")
	return err == nil
}

func (windowsBanBackend) Write(reason, duration string) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\OpenTunnel`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.SetStringValue("BanReason", reason)
	k.SetStringValue("BanDuration", duration)
}

// clearRegistryBan removes the registry half of a hard ban (best effort).
func (windowsBanBackend) Clear() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\OpenTunnel`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue("BanReason")
	_ = k.DeleteValue("BanDuration")
}
