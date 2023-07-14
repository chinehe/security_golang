package sha

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// DigestSHA256 SHA256实现
var DigestSHA256 = &digestSHA256{}

type digestSHA256 struct {
}

func (*digestSHA256) BytesDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA256) StringDigest(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func (*digestSHA256) ReaderDigest(data io.Reader) (string, error) {
	hash := sha256.New()
	buf := make([]byte, 1024)
	for {
		l, err := data.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		hash.Write(buf[:l])
	}
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum[:]), nil
}
