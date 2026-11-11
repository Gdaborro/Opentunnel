package protocol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestConcurrentSecureWritesStayDecryptable(t *testing.T) {
	c, s := net.Pipe()
	salt := RandomSalt()
	writer, err := ClientSideSecureStream(c, "synthetic-token", salt, ProfileParams{})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := ServerSideSecureStream(s, "synthetic-token", salt)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	defer reader.Close()
	_ = reader.SetDeadline(time.Now().Add(5 * time.Second))
	const writers, chunk = 24, 2048
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(b byte) {
			defer wg.Done()
			if _, err := writer.Write(bytes.Repeat([]byte{b}, chunk)); err != nil {
				t.Error(err)
			}
		}(byte(i))
	}
	data := make([]byte, writers*chunk)
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatalf("concurrent frames desynchronized: %v", err)
	}
	wg.Wait()
	counts := make([]int, writers)
	for _, b := range data {
		if int(b) >= writers {
			t.Fatal("corrupt decrypted data")
		}
		counts[b]++
	}
	for _, count := range counts {
		if count != chunk {
			t.Fatal("concurrent payload lost or duplicated")
		}
	}
}

type shortFrameWriter struct{ sliceSource }

func (s *shortFrameWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestSecureStreamRejectsSilentShortWrite(t *testing.T) {
	stream, err := ClientSideSecureStream(&shortFrameWriter{}, "synthetic-token", RandomSalt(), ProfileParams{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial encrypted frame reported success: %v", err)
	}
}
