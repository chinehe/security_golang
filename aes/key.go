package aes

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"time"
)

// GenerateAESKey 生成AES Key
func GenerateAESKey(byteSize int) []byte {
	keyBuf := bytes.Buffer{}
	for i := 0; i < byteSize; i++ {
		keyBuf.WriteByte(byte(rand.Intn(256)))
	}
	return keyBuf.Bytes()
}

// GenerateBase64AESKey 生成Base64 AES Key
func GenerateBase64AESKey(byteSize int) string {
	return base64.StdEncoding.EncodeToString(GenerateAESKey(byteSize))
}

func init() {
	rand.Seed(time.Now().Unix())
}
