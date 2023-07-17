package sha

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// DigestSHA384 SHA384实现
var DigestSHA384 = &digestSHA384{}

type digestSHA384 struct {
}

func (*digestSHA384) BytesDigest(data []byte) string {
	sum := sha512.Sum384(data)
	return hex.EncodeToString(sum[:])
}

func (*digestSHA384) ReaderDigest(data io.Reader) (string, error) {
	hash := sha512.New384()
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
