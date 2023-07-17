package hmac

import (
	"crypto/hmac"
	"encoding/hex"
	"hash"
	"io"
)

// BytesDigester 字节数组摘要
func BytesDigester(hash func() hash.Hash, data []byte, key []byte) string {
	hmacHash := hmac.New(hash, key)
	hmacHash.Write(data)
	sum := hmacHash.Sum(nil)
	return hex.EncodeToString(sum)
}

// ReaderDigester 读取器摘要
func ReaderDigester(hash func() hash.Hash, data io.Reader, key []byte) (string, error) {
	hmacHash := hmac.New(hash, key)
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
func Verify(hash func() hash.Hash, data []byte, key []byte, sign string) (bool, error) {
	signBytes, err := hex.DecodeString(sign)
	if err != nil {
		return false, err
	}
	hmacHash := hmac.New(hash, key)
	hmacHash.Write(data)
	sum := hmacHash.Sum(nil)
	return hmac.Equal(signBytes, sum), nil
}
