package sha

import (
	"strings"
	"testing"
)

func TestBytesDigestSha512(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA512.BytesDigest(data))
	t.Log(DigestSHA512.StringDigest("Hello World"))
	t.Log(DigestSHA512.ReaderDigest(strings.NewReader("Hello World")))
}
