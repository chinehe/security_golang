package sha

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// DigestSHA224 SHA224实现
var DigestSHA224 = &digestSHA224{}

type digestSHA224 struct {
}

func (*digestSHA224) BytesDigest(data []byte) string {
	sum := sha256.Sum224(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA224) StringDigest(data string) string {
	sum := sha256.Sum224([]byte(data))
	return hex.EncodeToString(sum[:])
}

func (*digestSHA224) ReaderDigest(data io.Reader) (string, error) {
	hash := sha256.New224()
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
