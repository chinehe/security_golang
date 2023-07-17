package sha

import (
	"strings"
	"testing"
)

func TestBytesDigest(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA1.BytesDigest(data))
	t.Log(DigestSHA1.ReaderDigest(strings.NewReader("Hello World")))
}
