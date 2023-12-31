package md5

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

type Digester struct {
}

func (g *Digester) BytesDigest(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

func (g *Digester) ReaderDigest(data io.Reader) (string, error) {
	m := md5.New()
	buf := make([]byte, 1024)
	for {
		l, err := data.Read(buf)
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
