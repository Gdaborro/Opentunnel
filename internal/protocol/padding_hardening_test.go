package protocol

import "testing"

func TestNamedPaddingActuallyReachesSizeBucketsAndRespectsFrameLimit(t *testing.T) {
	s := &SecureStream{params: ProfileFor("balanced")}
	for _, test := range []struct{ payload, bucket int }{{1, 64}, {100, 256}, {300, 1024}, {1200, 4096}, {5000, 16384}, {20000, 32768}} {
		for range 100 {
			size := 2 + test.payload + s.padLen(test.payload)
			if size < test.bucket || size > maxPlaintext {
				t.Fatalf("payload %d did not reach bounded bucket %d (size=%d)", test.payload, test.bucket, size)
			}
		}
	}
	for range 100 {
		if size := maxPlaintext + s.padLen(maxPlaintext-2); size > maxPlaintext {
			t.Fatal("largest frame padding exceeded limit")
		}
	}
}
