// tlsprofile.go narrows Go's default TLS profile to what a stock
// nginx/Cloudflare origin serves. Go's defaults leak the toolchain: it
// accepts static-RSA and CBC suites (no PFS, a decade out of fashion) and
// negotiates the X25519MLKEM768 post-quantum group (Go >= 1.24 default;
// Ubuntu's OpenSSL 3.0 does not offer it) — both are passive Go-server
// tells an auditor flags.
package transport

import (
	"crypto/tls"
)

// RealisticTLS applies the origin-realistic TLS profile in place.
func RealisticTLS(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return cfg
	}
	cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	cfg.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	return cfg
}
