package rsa

import (
	"fmt"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	fmt.Println(GenerateKey(4096))
	fmt.Println(GenerateKey(2048))
	fmt.Println(GenerateKey(1024))
	fmt.Println(GenerateKey(512))
}

func TestGenerateMarshalledKey(t *testing.T) {
	fmt.Println(GenerateMarshalledKey(1024, PrivateKeyMarshallerPKCS1, PublicKeyMarshallerPKCS1))
	fmt.Println(GenerateMarshalledKey(1024, PrivateKeyMarshallerPKCS1, PublicKeyMarshallerPKIX))
	fmt.Println(GenerateMarshalledKey(1024, PrivateKeyMarshallerPKCS8, PublicKeyMarshallerPKCS1))
	fmt.Println(GenerateMarshalledKey(1024, PrivateKeyMarshallerPKCS8, PublicKeyMarshallerPKIX))
}

func TestGeneratePemKey(t *testing.T) {
	fmt.Println(GeneratePemKey(1024, PrivateKeyMarshallerPKCS1, PublicKeyMarshallerPKCS1))
	fmt.Println(GeneratePemKey(1024, PrivateKeyMarshallerPKCS1, PublicKeyMarshallerPKIX))
	fmt.Println(GeneratePemKey(1024, PrivateKeyMarshallerPKCS8, PublicKeyMarshallerPKCS1))
	fmt.Println(GeneratePemKey(1024, PrivateKeyMarshallerPKCS8, PublicKeyMarshallerPKIX))
}
