package transport

import (
	"sync"

	utls "github.com/refraction-networking/utls"
)

// utlsSessionCache is a minimal ClientSessionCache for uTLS dials (the
// stdlib LRU cache speaks crypto/tls session-state types, not utls's).
// Shared process-wide like sessionCache so resumed handshakes work on the
// Chrome-hello tiers too.
type utlsSessionCache struct {
	mu sync.Mutex
	m  map[string]*utls.ClientSessionState
}

func newUTLSSessionCache() *utlsSessionCache {
	return &utlsSessionCache{m: map[string]*utls.ClientSessionState{}}
}

func (c *utlsSessionCache) Get(sessionKey string) (*utls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.m[sessionKey]
	return s, ok
}

func (c *utlsSessionCache) Put(sessionKey string, cs *utls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs == nil {
		delete(c.m, sessionKey)
		return
	}
	if len(c.m) >= 64 {
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
	c.m[sessionKey] = cs
}
