package aes

import (
	"encoding/base64"
	"security"
	"testing"
)

func TestCTR(t *testing.T) {
	data := []byte("123456789")
	key := []byte("1234567890123456")
	encryptor := CTREncryptor{
		Key:     key,
		Padding: security.PKCS7Padding,
	}
	encrypt, err := encryptor.Encrypt(data)
	if err != nil {
		t.Error(err)
	}
	encodeToString := base64.StdEncoding.EncodeToString(encrypt)
	t.Logf("encrypted:%v", encodeToString)

	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Logf("decrypted:%v", string(decrypt))
}
