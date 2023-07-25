package hmac

import (
	"crypto/hmac"
	"encoding/hex"
	"hash"
	"io"
)

type Digester struct {
	Hash func() hash.Hash // hash func
	Key  []byte           // key
}

// BytesDigest 字节数组摘要
func (g *Digester) BytesDigest(data []byte) string {
	hmacHash := hmac.New(g.Hash, g.Key)
	hmacHash.Write(data)
	sum := hmacHash.Sum(nil)
	return hex.EncodeToString(sum)
}

// ReaderDigest 读取器摘要
func (g *Digester) ReaderDigest(data io.Reader) (string, error) {
	hmacHash := hmac.New(g.Hash, g.Key)
	buf := make([]byte, 1024)
	for {
		l, err := data.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		hmacHash.Write(buf[:l])
	}
	sum := hmacHash.Sum(nil)
	return hex.EncodeToString(sum), nil
}

// Verify 校验签名
func (g *Digester) Verify(data []byte, sign string) (bool, error) {
	signBytes, err := hex.DecodeString(sign)
	if err != nil {
		return false, err
	}
	hmacHash := hmac.New(g.Hash, g.Key)
	hmacHash.Write(data)
	sum := hmacHash.Sum(nil)
	return hmac.Equal(signBytes, sum), nil
}
