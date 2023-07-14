package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"security/sha"
)

// Sign 签名
// RSAWithSHA1 PKCS1v15
func Sign(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	sha1 := sha.Sha1(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, sha1)
}

// SignBase64 签名并转成base64字符串
// RSAWithSHA1 PKCS1v15
func SignBase64(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	sha1 := sha.Sha1(data)
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, sha1)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// Sign256 签名
// RSAWithSHA256 PKCS1v15
func Sign256(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	sha256 := sha.Sha256(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sha256)
}

// Sign256Base64 签名并转成base64字符串
// RSAWithSHA256 PKCS1v15
func Sign256Base64(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	sha256 := sha.Sha256(data)
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sha256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// SignWithMarshalledKey 签名
// RSAWithSHA1 PKCS1v15
func SignWithMarshalledKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) ([]byte, error) {
	privateKey, err := privateKeyMarshaller.Unmarshal(privateKeyStr)
	if err != nil {
		return nil, err
	}
	sha1 := sha.Sha1(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, sha1)
}

// SignBase64WithMarshalledKey 签名并转成base64字符串
// RSAWithSHA1 PKCS1v15
func SignBase64WithMarshalledKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) (string, error) {
	privateKey, err := privateKeyMarshaller.Unmarshal(privateKeyStr)
	if err != nil {
		return "", err
	}
	sha1 := sha.Sha1(data)
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, sha1)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// Sign256WithMarshalledKey 签名
// RSAWithSHA256 PKCS1v15
func Sign256WithMarshalledKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) ([]byte, error) {
	privateKey, err := privateKeyMarshaller.Unmarshal(privateKeyStr)
	if err != nil {
		return nil, err
	}
	sha256 := sha.Sha256(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sha256)
}

// Sign256Base64WithMarshalledKey 签名并转成base64字符串
// RSAWithSHA256 PKCS1v15
func Sign256Base64WithMarshalledKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) (string, error) {
	privateKey, err := privateKeyMarshaller.Unmarshal(privateKeyStr)
	if err != nil {
		return "", err
	}
	sha256 := sha.Sha256(data)
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sha256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// SignWithPemKey 签名
// RSAWithSHA1 PKCS1v15
func SignWithPemKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) ([]byte, error) {
	privateKey, err := privateKeyMarshaller.PemDecode(privateKeyStr)
	if err != nil {
		return nil, err
	}
	sha1 := sha.Sha1(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, sha1)
}

// SignBase64WithPemKey 签名并转成base64字符串
// RSAWithSHA1 PKCS1v15
func SignBase64WithPemKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) (string, error) {
	privateKey, err := privateKeyMarshaller.PemDecode(privateKeyStr)
	if err != nil {
		return "", err
	}
	sha1 := sha.Sha1(data)
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, sha1)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// Sign256WithPemKey 签名
// RSAWithSHA256 PKCS1v15
func Sign256WithPemKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) ([]byte, error) {
	privateKey, err := privateKeyMarshaller.PemDecode(privateKeyStr)
	if err != nil {
		return nil, err
	}
	sha256 := sha.Sha256(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sha256)
}

// Sign256Base64WithPemKey 签名并转成base64字符串
// RSAWithSHA256 PKCS1v15
func Sign256Base64WithPemKey(privateKeyStr string, data []byte, privateKeyMarshaller PrivateKeyMarshaller) (string, error) {
	privateKey, err := privateKeyMarshaller.PemDecode(privateKeyStr)
	if err != nil {
		return "", err
	}
	sha256 := sha.Sha256(data)
	bytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sha256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// Verify 验签
// RSAWithSHA1 PKCS1v15
func Verify(publicKey *rsa.PublicKey, data []byte, sign []byte) error {
	sha1 := sha.Sha1(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, sha1, sign)
}

// VerifyBase64 验签base64
// RSAWithSHA1 PKCS1v15
func VerifyBase64(publicKey *rsa.PublicKey, data []byte, signStr string) error {
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	sha1 := sha.Sha1(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, sha1, sign)
}

// Verify256 验签
// RSAWithSHA256 PKCS1v15
func Verify256(publicKey *rsa.PublicKey, data []byte, sign []byte) error {
	sha256 := sha.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256, sign)
}

// Verify256Base64 验签base64
// RSAWithSHA256 PKCS1v15
func Verify256Base64(publicKey *rsa.PublicKey, data []byte, signStr string) error {
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	sha256 := sha.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256, sign)
}

// VerifyWithMarshalledKey 验签
// RSAWithSHA1 PKCS1v15
func VerifyWithMarshalledKey(publicKeyStr string, data []byte, sign []byte, publicKeyMarshaller PublicKeyMarshaller) error {
	publicKey, err := publicKeyMarshaller.Unmarshal(publicKeyStr)
	if err != nil {
		return err
	}
	sha1 := sha.Sha1(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, sha1, sign)
}

// VerifyBase64WithMarshalledKey 验签base64
// RSAWithSHA1 PKCS1v15
func VerifyBase64WithMarshalledKey(publicKeyStr string, data []byte, signStr string, publicKeyMarshaller PublicKeyMarshaller) error {
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	publicKey, err := publicKeyMarshaller.Unmarshal(publicKeyStr)
	if err != nil {
		return err
	}
	sha1 := sha.Sha1(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, sha1, sign)
}

// Verify256WithMarshalledKey 验签
// RSAWithSHA256 PKCS1v15
func Verify256WithMarshalledKey(publicKeyStr string, data []byte, sign []byte, publicKeyMarshaller PublicKeyMarshaller) error {
	publicKey, err := publicKeyMarshaller.Unmarshal(publicKeyStr)
	if err != nil {
		return err
	}
	sha256 := sha.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256, sign)
}

// Verify256Base64WithMarshalledKey 验签base64
// RSAWithSHA256 PKCS1v15
func Verify256Base64WithMarshalledKey(publicKeyStr string, data []byte, signStr string, publicKeyMarshaller PublicKeyMarshaller) error {
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	publicKey, err := publicKeyMarshaller.Unmarshal(publicKeyStr)
	if err != nil {
		return err
	}
	sha256 := sha.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256, sign)
}

// VerifyWithPemKey 验签
// RSAWithSHA1 PKCS1v15
func VerifyWithPemKey(publicKeyStr string, data []byte, sign []byte, publicKeyMarshaller PublicKeyMarshaller) error {
	publicKey, err := publicKeyMarshaller.PemDecode(publicKeyStr)
	if err != nil {
		return err
	}
	sha1 := sha.Sha1(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, sha1, sign)
}

// VerifyBase64WithPemKey 验签base64
// RSAWithSHA1 PKCS1v15
func VerifyBase64WithPemKey(publicKeyStr string, data []byte, signStr string, publicKeyMarshaller PublicKeyMarshaller) error {
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	publicKey, err := publicKeyMarshaller.PemDecode(publicKeyStr)
	if err != nil {
		return err
	}
	sha1 := sha.Sha1(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, sha1, sign)
}

// Verify256WithPemKey 验签
// RSAWithSHA256 PKCS1v15
func Verify256WithPemKey(publicKeyStr string, data []byte, sign []byte, publicKeyMarshaller PublicKeyMarshaller) error {
	publicKey, err := publicKeyMarshaller.PemDecode(publicKeyStr)
	if err != nil {
		return err
	}
	sha256 := sha.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256, sign)
}

// Verify256Base64WithPemKey 验签base64
// RSAWithSHA256 PKCS1v15
func Verify256Base64WithPemKey(publicKeyStr string, data []byte, signStr string, publicKeyMarshaller PublicKeyMarshaller) error {
	sign, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	publicKey, err := publicKeyMarshaller.PemDecode(publicKeyStr)
	if err != nil {
		return err
	}
	sha256 := sha.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256, sign)
}
