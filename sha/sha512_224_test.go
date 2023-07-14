package sha

import (
	"strings"
	"testing"
)

func TestBytesDigestSha512_224(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA512_224.BytesDigest(data))
	t.Log(DigestSHA512_224.StringDigest("Hello World"))
	t.Log(DigestSHA512_224.ReaderDigest(strings.NewReader("Hello World")))
}
