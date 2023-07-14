package md5

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

func ByteDigest(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

func StringDigest(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func ReaderDigest(reader io.Reader) (string, error) {
	m := md5.New()
	buf := make([]byte, 1024)
	for {
		l, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		m.Write(buf[:l])
	}
	sum := m.Sum(nil)
	return hex.EncodeToString(sum), nil
}
