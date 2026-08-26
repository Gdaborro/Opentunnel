// Package share builds and parses opentunnel configuration share links
// (otu://...) and renders them as QR codes.
package share

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Params is everything a client needs to connect. Treat links as secrets:
// they embed the auth token.
type Params struct {
	ServerAddr  string `json:"a"`
	Token       string `json:"t"`
	Fingerprint string `json:"f,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
	WSPath      string `json:"w,omitempty"`
	Profile     string `json:"p,omitempty"` // auto|fast|balanced|stealth
	Mux         *bool  `json:"m,omitempty"`
	UDP         *bool  `json:"u,omitempty"`
}

// Build encodes params into an otu:// link.
func Build(p Params) (string, error) {
	if p.ServerAddr == "" || p.Token == "" {
		return "", fmt.Errorf("share: server_addr and token are required")
	}
	raw, err := json.Marshal(&p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	return "otu://" + enc, nil
}

// Parse decodes an otu:// link.
func Parse(link string) (*Params, error) {
	if !strings.HasPrefix(link, "otu://") {
		return nil, fmt.Errorf("share: not an otu:// link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "otu://"))
	if err != nil {
		return nil, fmt.Errorf("share: bad encoding: %w", err)
	}
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("share: bad contents: %w", err)
	}
	if p.ServerAddr == "" || p.Token == "" {
		return nil, fmt.Errorf("share: incomplete link")
	}
	return &p, nil
}

// QRText renders the link as a scannable ASCII QR code for terminals.
func QRText(link string) (string, error) {
	qr, err := qrEncode(link)
	if err != nil {
		return "", err
	}
	return qr.ToSmallString(false), nil
}

// QRPNGFile writes the link as a PNG QR code at the given size.
func QRPNGFile(link, path string, size int) error {
	return qrPNG(link, size, path)
}
