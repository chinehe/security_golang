package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

// Encrypt RSA 加密
func Encrypt(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

// EncryptWithMarshalledKey RSA 加密
func EncryptWithMarshalledKey(publicKey string, data []byte, publicKeyMarshaller PublicKeyMarshaller) ([]byte, error) {
	publicKeyBytes, err := publicKeyMarshaller.Unmarshal(publicKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, publicKeyBytes, data)
}

// EncryptWithPemKey RSA 加密
func EncryptWithPemKey(publicKey string, data []byte, publicKeyMarshaller PublicKeyMarshaller) ([]byte, error) {
	publicKeyBytes, err := publicKeyMarshaller.PemDecode(publicKey)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, publicKeyBytes, data)
}

// Decrypt RSA解密
func Decrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

// DecryptWithMarshalledKey RSA解密
func DecryptWithMarshalledKey(privateKey string, cipherText []byte, privateKeyMarshaller PrivateKeyMarshaller) ([]byte, error) {
	privateKeyBytes, err := privateKeyMarshaller.Unmarshal(privateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKeyBytes, cipherText)
}

// DecryptWithPemKey RSA解密
func DecryptWithPemKey(privateKey string, cipherText []byte, privateKeyMarshaller PrivateKeyMarshaller) ([]byte, error) {
	privateKeyBytes, err := privateKeyMarshaller.PemDecode(privateKey)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKeyBytes, cipherText)
}
