package aes

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"time"
)

// GenerateDESKey 生成DES Key
func GenerateDESKey() []byte {
	keyBuf := bytes.Buffer{}
	for i := 0; i < 8; i++ {
		keyBuf.WriteByte(byte(rand.Intn(256)))
	}
	return keyBuf.Bytes()
}

// GenerateBase64DESKey 生成Base64 DES Key
func GenerateBase64DESKey() string {
	return base64.StdEncoding.EncodeToString(GenerateDESKey())
}

func init() {
	rand.Seed(time.Now().Unix())
}
