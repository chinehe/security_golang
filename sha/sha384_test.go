package sha

import (
	"strings"
	"testing"
)

func TestBytesDigestSha384(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA384.BytesDigest(data))
	t.Log(DigestSHA384.StringDigest("Hello World"))
	t.Log(DigestSHA384.ReaderDigest(strings.NewReader("Hello World")))
}
