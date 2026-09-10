package protocol

// WebSocket endpoint paths. DefaultWSPath is deliberately boring: under TLS
// interception the upgrade request is plaintext, and "/ws" plus a custom
// subprotocol screams purpose-built tunnel. LegacyWSPath stays mounted on
// the server so old clients keep working during migration.
const (
	DefaultWSPath = "/api/v1/stream"
	LegacyWSPath  = "/ws"
)
