package sha

import (
	"strings"
	"testing"
)

func TestBytesDigestSha256(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA256.BytesDigest(data))
	t.Log(DigestSHA256.StringDigest("Hello World"))
	t.Log(DigestSHA256.ReaderDigest(strings.NewReader("Hello World")))
}
