package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

// GenerateKey 生成RSA公私钥
func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey, err
}

// GenerateMarshalledKey 生成RSA公私钥并按照指定格式进行格式化
func GenerateMarshalledKey(bits int, privateKeyMarshaller PrivateKeyMarshaller, publicKeyMarshaller PublicKeyMarshaller) (string, string, error) {
	privateKey, publicKey, err := GenerateKey(bits)
	if err != nil {
		return "", "", err
	}
	privateResult, err := privateKeyMarshaller.Marshal(privateKey)
	if err != nil {
		return "", "", err
	}
	publicResult, err := publicKeyMarshaller.Marshal(publicKey)
	if err != nil {
		return "", "", err
	}
	return privateResult, publicResult, nil
}

// GeneratePemKey 生成RSA公私钥并按照指定格式进行格式化,然后pem格式化
func GeneratePemKey(bits int, privateKeyMarshaller PrivateKeyMarshaller, publicKeyMarshaller PublicKeyMarshaller) (string, string, error) {
	privateKey, publicKey, err := GenerateKey(bits)
	if err != nil {
		return "", "", err
	}
	pemPrivateKey, err := privateKeyMarshaller.PemEncode(privateKey)
	if err != nil {
		return "", "", err
	}
	pemPublicKey, err := publicKeyMarshaller.PemEncode(publicKey)
	if err != nil {
		return "", "", err
	}
	return pemPrivateKey, pemPublicKey, nil
}
