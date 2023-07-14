package rsa

import (
	"fmt"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	privateKey, publicKey, _ := GenerateKey(1024)
	data := []byte("Hello World")
	sign, _ := Sign(privateKey, data)
	fmt.Println(string(sign))
	fmt.Println(Verify(publicKey, data, sign))

	sign, _ = Sign256(privateKey, data)
	t.Log(string(sign))
	t.Log(Verify256(publicKey, data, sign))
}

func TestSignAndVerifyBase64(t *testing.T) {
	privateKey, publicKey, _ := GenerateMarshalledKey(2048, PrivateKeyMarshallerPKCS1, PublicKeyMarshallerPKCS1)
	data := []byte("Hello World")
	sign, _ := SignBase64WithMarshalledKey(privateKey, data, PrivateKeyMarshallerPKCS1)
	fmt.Println(string(sign))
	fmt.Println(VerifyBase64WithMarshalledKey(publicKey, data, sign, PublicKeyMarshallerPKCS1))

	sign, _ = Sign256Base64WithMarshalledKey(privateKey, data, PrivateKeyMarshallerPKCS1)
	t.Log(string(sign))
	t.Log(Verify256Base64WithMarshalledKey(publicKey, data, sign, PublicKeyMarshallerPKCS1))
}

func TestSignAndVerifyPem(t *testing.T) {
	privateKey, publicKey, _ := GeneratePemKey(2048, PrivateKeyMarshallerPKCS8, PublicKeyMarshallerPKIX)
	data := []byte("Hello World")
	sign, _ := SignBase64WithPemKey(privateKey, data, PrivateKeyMarshallerPKCS8)
	fmt.Println(string(sign))
	fmt.Println(VerifyBase64WithPemKey(publicKey, data, sign, PublicKeyMarshallerPKIX))

	sign, _ = Sign256Base64WithPemKey(privateKey, data, PrivateKeyMarshallerPKCS8)
	t.Log(string(sign))
	t.Log(Verify256Base64WithPemKey(publicKey, data, sign, PublicKeyMarshallerPKIX))
}
