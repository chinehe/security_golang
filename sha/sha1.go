package sha

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
)

// DigestSHA1 SHA1 实现
var DigestSHA1 = &digestSHA1{}

type digestSHA1 struct {
}

func (*digestSHA1) BytesDigest(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA1) ReaderDigest(data io.Reader) (string, error) {
	hash := sha1.New()
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
