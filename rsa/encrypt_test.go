package rsa

import (
	"testing"
)

func TestEncryptAndDecryptWithPemKey(t *testing.T) {
	privateKey, publicKey, _ := GeneratePemKey(2048, PrivateKeyMarshallerPKCS1, PublicKeyMarshallerPKIX)
	encrypt, _ := EncryptWithPemKey(publicKey, []byte("Hello World"), PublicKeyMarshallerPKIX)
	decrypt, _ := DecryptWithPemKey(privateKey, encrypt, PrivateKeyMarshallerPKCS1)
	t.Log(string(decrypt))
}

func TestEncryptAndDecryptWithMarshalledKey(t *testing.T) {
	privateKey, publicKey, _ := GenerateMarshalledKey(2048, PrivateKeyMarshallerPKCS8, PublicKeyMarshallerPKCS1)
	encrypt, _ := EncryptWithMarshalledKey(publicKey, []byte("Hello World"), PublicKeyMarshallerPKCS1)
	decrypt, _ := DecryptWithMarshalledKey(privateKey, encrypt, PrivateKeyMarshallerPKCS8)
	t.Log(string(decrypt))
}
func TestEncryptAndDecrypt(t *testing.T) {
	privateKey, publicKey, _ := GenerateKey(2048)
	encrypt, _ := Encrypt(publicKey, []byte("Hello World"))
	decrypt, _ := Decrypt(privateKey, encrypt)
	t.Log(string(decrypt))
}
