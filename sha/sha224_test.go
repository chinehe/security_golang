package sha

import (
	"strings"
	"testing"
)

func TestSHA224(t *testing.T) {
	data := []byte("Hello World")
	t.Log(DigestSHA224.BytesDigest(data))
	t.Log(DigestSHA224.ReaderDigest(strings.NewReader("Hello World")))
}
