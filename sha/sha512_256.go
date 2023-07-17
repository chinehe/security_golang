package sha

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// DigestSHA512_256 SHA512_256实现
var DigestSHA512_256 = &digestSHA512_256{}

type digestSHA512_256 struct {
}

func (*digestSHA512_256) BytesDigest(data []byte) string {
	sum := sha512.Sum512_256(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA512_256) ReaderDigest(data io.Reader) (string, error) {
	hash := sha512.New512_256()
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
