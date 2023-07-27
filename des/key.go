package aes

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

const (
	KeySizeDES  = 8
	KeySize3DES = 24
)

// GenerateDESKey 生成DES Key
func GenerateDESKey(keySize int) ([]byte, error) {
	if keySize != KeySizeDES && keySize != KeySize3DES {
		return nil, fmt.Errorf("invalid key size:%d", keySize)
	}
	keyBuf := bytes.Buffer{}
	for i := 0; i < keySize; i++ {
		keyBuf.WriteByte(byte(rand.Intn(256)))
	}
	return keyBuf.Bytes(), nil
}

// GenerateBase64DESKey 生成Base64 DES Key
func GenerateBase64DESKey(keySize int) (string, error) {
	key, err := GenerateDESKey(keySize)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func init() {
	rand.Seed(time.Now().Unix())
}
