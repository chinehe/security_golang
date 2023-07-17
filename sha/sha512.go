package sha

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// DigestSHA512 SHA512实现
var DigestSHA512 = &digestSHA512{}

type digestSHA512 struct {
}

func (*digestSHA512) BytesDigest(data []byte) string {
	sum := sha512.Sum512(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA512) ReaderDigest(data io.Reader) (string, error) {
	hash := sha512.New()
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
