package share

import (
	"strings"
	"testing"
)

func TestLinkRoundtrip(t *testing.T) {
	muxTrue, udpFalse := true, false
	p := Params{
		ServerAddr:  "vpn.example.com:443",
		Token:       "s3cret-token",
		Fingerprint: strings.Repeat("ab", 32),
		WSPath:      "/ws",
		Profile:     "auto",
		Mux:         &muxTrue,
		UDP:         &udpFalse,
	}
	link, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "otu://") {
		t.Fatalf("bad prefix: %q", link)
	}
	got, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.ServerAddr != p.ServerAddr || got.Token != p.Token ||
		got.Fingerprint != p.Fingerprint || got.Profile != p.Profile ||
		*got.Mux != true || *got.UDP != false {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, p)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse("https://example.com"); err == nil {
		t.Fatal("wrong scheme must fail")
	}
	if _, err := Parse("otu://!!!not-base64"); err == nil {
		t.Fatal("bad encoding must fail")
	}
	link, _ := Build(Params{ServerAddr: "x:443"}) // missing token
	if link != "" {
		_, err := Parse(link)
		if err == nil && link != "" && !strings.HasPrefix(link, "otu://") {
			t.Fatal("incomplete params must not produce valid link")
		}
	}
}

func TestQRTextRenders(t *testing.T) {
	link, err := Build(Params{ServerAddr: "h:443", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	txt, err := QRText(link)
	if err != nil {
		t.Fatalf("qr: %v", err)
	}
	if len(txt) < 20 || !strings.Contains(txt, "\n") {
		t.Fatal("qr text suspiciously small")
	}
}
