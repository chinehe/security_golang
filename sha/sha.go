package sha

import (
	"crypto/sha1"
	"crypto/sha256"
)

// Sha1 Calculate the sha1 hash
func Sha1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// Sha256 Calculate the sha256 hash
func Sha256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
