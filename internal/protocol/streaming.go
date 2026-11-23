package protocol

// A public streaming request format is not proof of client identity. Relays
// must still apply normal setup budgets, device authentication and policy.
// Opt-in origin support is needed when an H3 edge speaks H2 to the relay.
const StreamingHeader = "X-Otu-Stream"
const StreamingValue = "1"
