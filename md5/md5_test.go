package md5

import (
	"strings"
	"testing"
)

func TestByteDigest(t *testing.T) {
	data := []byte("Hello World")
	t.Log(ByteDigest(data))
}

func TestReaderDigest(t *testing.T) {
	reader := strings.NewReader("Hello World")
	t.Log(ReaderDigest(reader))
}
