package sha

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// DigestSHA512_224 SHA512_224实现
var DigestSHA512_224 = &digestSHA512_224{}

type digestSHA512_224 struct {
}

func (*digestSHA512_224) BytesDigest(data []byte) string {
	sum := sha512.Sum512_224(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA512_224) ReaderDigest(data io.Reader) (string, error) {
	hash := sha512.New512_224()
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
