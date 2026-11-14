//go:build windows

package client

type banBackend interface {
	Banned() bool
	Write(string, string)
	Clear()
}

func isRegistryBanned() bool                   { return banState.Banned() }
func writeRegistryBan(reason, duration string) { banState.Write(reason, duration) }
func clearRegistryBan()                        { banState.Clear() }
