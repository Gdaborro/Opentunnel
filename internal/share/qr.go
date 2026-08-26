package share

import (
	qrcode "github.com/skip2/go-qrcode"
)

func qrEncode(s string) (*qrcode.QRCode, error) {
	return qrcode.New(s, qrcode.Medium)
}

func qrPNG(s string, size int, path string) error {
	return qrcode.WriteFile(s, qrcode.Medium, size, path)
}
