package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDeriveKeysDeterministic(t *testing.T) {
	salt := RandomSalt()
	a1, b1, err := DeriveKeys("tok", salt)
	if err != nil {
		t.Fatal(err)
	}
	a2, b2, _ := DeriveKeys("tok", salt)
	if !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
		t.Fatal("key derivation not deterministic")
	}
	if bytes.Equal(a1, b1) {
		t.Fatal("direction keys must differ")
	}
	a3, _, _ := DeriveKeys("tok", RandomSalt())
	if bytes.Equal(a1, a3) {
		t.Fatal("keys must change with salt")
	}
	if _, _, err := DeriveKeys("tok", []byte("short")); err == nil {
		t.Fatal("bad salt size must be rejected")
	}
}

func TestSecureStreamEcho(t *testing.T) {
	for _, params := range []ProfileParams{{}, {Padding: true}, {Padding: true, MaxJitter: time.Millisecond}} {
		c, s := tcpPipe(t)
		salt := RandomSalt()
		payload := bytes.Repeat([]byte("x-tunnel-payload-"), 3000) // >16KB forces chunking

		go func() {
			cs, err := ClientSideSecureStream(c, "shared", salt, params)
			if err != nil {
				return
			}
			defer cs.Close()
			io.Copy(cs, cs) // echo everything back
		}()
		ss, err := ServerSideSecureStream(s, "shared", salt)
		if err != nil {
			t.Fatalf("server stream: %v", err)
		}
		done := make(chan struct{})
		go func() {
			_, _ = ss.Write(payload)
			close(done)
		}()
		got := make([]byte, len(payload))
		total := 0
		for total < len(payload) {
			n, err := ss.Read(got[total:])
			if err != nil {
				t.Fatalf("read (padding=%v): %v", params.Padding, err)
			}
			total += n
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch (padding=%v)", params.Padding)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("writer never finished")
		}
		ss.Close()
	}
}

func TestSecureStreamTamperDetected(t *testing.T) {
	c, s := tcpPipe(t)
	defer c.Close()
	salt := RandomSalt()
	cs, err := ClientSideSecureStream(c, "k", salt, ProfileParams{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	// Extract the single frame from the wire and corrupt one ciphertext byte.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatal(err)
	}
	ctLen := binary.BigEndian.Uint32(hdr)
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(s, ct); err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-3] ^= 0xFF

	src := &sliceSource{data: append(append([]byte{}, hdr...), ct...)}
	ss, err := ServerSideSecureStream(src, "k", salt)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := ss.Read(buf); err == nil {
		t.Fatal("tampered frame must fail to decrypt")
	}
}

// sliceSource is a net.Conn that yields fixed bytes once, then EOF.
type sliceSource struct {
	data []byte
	pos  int
}

func (s *sliceSource) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}
func (s *sliceSource) Write(p []byte) (int, error)        { return len(p), nil }
func (s *sliceSource) Close() error                       { return nil }
func (s *sliceSource) LocalAddr() net.Addr                { return dummyAddr{} }
func (s *sliceSource) RemoteAddr() net.Addr               { return dummyAddr{} }
func (s *sliceSource) SetDeadline(t time.Time) error      { return nil }
func (s *sliceSource) SetReadDeadline(t time.Time) error  { return nil }
func (s *sliceSource) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

var _ = errors.New // keep errors imported for future assertions

func TestReplayCache(t *testing.T) {
	rc := NewReplayCache(50*time.Millisecond, 100)
	salt := []byte("0123456789abcdef")
	if !rc.CheckAndAdd(salt) {
		t.Fatal("first sighting must pass")
	}
	if rc.CheckAndAdd(salt) {
		t.Fatal("replay must be rejected")
	}
	time.Sleep(60 * time.Millisecond)
	if !rc.CheckAndAdd(salt) {
		t.Fatal("salt must expire after TTL")
	}
}
