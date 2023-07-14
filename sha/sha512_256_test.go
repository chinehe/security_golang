package sha

import (
	"strings"
	"testing"
)

func TestBytesDigestSha512_256(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA512_256.BytesDigest(data))
	t.Log(DigestSHA512_256.StringDigest("Hello World"))
	t.Log(DigestSHA512_256.ReaderDigest(strings.NewReader("Hello World")))
}
