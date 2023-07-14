package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

var (
	PrivateKeyMarshallerPKCS1 = &pkcs1PrivateKeyMarshaller{}
	PrivateKeyMarshallerPKCS8 = &pkcs8PrivateKeyMarshaller{}
	PublicKeyMarshallerPKCS1  = &pkcs1PublicKeyMarshaller{}
	PublicKeyMarshallerPKIX   = &pkixPublicKeyMarshaller{}
)

// PrivateKeyMarshaller 私钥Marshaller接口
type PrivateKeyMarshaller interface {
	Marshal(privateKey *rsa.PrivateKey) (string, error)
	Unmarshal(privateKey string) (*rsa.PrivateKey, error)
	PemEncode(privateKey *rsa.PrivateKey) (string, error)
	PemDecode(privateKey string) (*rsa.PrivateKey, error)
}

// pkcs1PrivateKeyMarshaller PKCS1格式私钥Marshaller
type pkcs1PrivateKeyMarshaller struct {
}

func (m *pkcs1PrivateKeyMarshaller) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	marshalPKCS1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	return base64.StdEncoding.EncodeToString(marshalPKCS1PrivateKey), nil
}

func (m *pkcs1PrivateKeyMarshaller) Unmarshal(privateKey string) (*rsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(bytes)
}

func (m *pkcs1PrivateKeyMarshaller) PemEncode(privateKey *rsa.PrivateKey) (string, error) {
	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1PrivateKey,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (m *pkcs1PrivateKeyMarshaller) PemDecode(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// pkcs8PrivateKeyMarshaller PKCS8格式私钥Marshaller
type pkcs8PrivateKeyMarshaller struct {
}

func (m *pkcs8PrivateKeyMarshaller) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pkcs8PrivateKey), err
}

func (m *pkcs8PrivateKeyMarshaller) Unmarshal(privateKey string) (*rsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}

func (m *pkcs8PrivateKeyMarshaller) PemEncode(privateKey *rsa.PrivateKey) (string, error) {
	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8PrivateKey,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (m *pkcs8PrivateKeyMarshaller) PemDecode(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pkcs8PrivateKey.(*rsa.PrivateKey), nil
}

// PublicKeyMarshaller 公钥Marshaller
type PublicKeyMarshaller interface {
	Marshal(publicKey *rsa.PublicKey) (string, error)
	Unmarshal(publicKey string) (*rsa.PublicKey, error)
	PemEncode(publicKey *rsa.PublicKey) (string, error)
	PemDecode(publicKey string) (*rsa.PublicKey, error)
}

// pkcs1PublicKeyMarshaller PKCS1格式公钥Marshaller
type pkcs1PublicKeyMarshaller struct {
}

func (*pkcs1PublicKeyMarshaller) Marshal(publicKey *rsa.PublicKey) (string, error) {
	pkcs1PublicKey := x509.MarshalPKCS1PublicKey(publicKey)
	return base64.StdEncoding.EncodeToString(pkcs1PublicKey), nil
}

func (m *pkcs1PublicKeyMarshaller) Unmarshal(publicKey string) (*rsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(bytes)
}

func (m *pkcs1PublicKeyMarshaller) PemEncode(publicKey *rsa.PublicKey) (string, error) {
	bytes := x509.MarshalPKCS1PublicKey(publicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (m *pkcs1PublicKeyMarshaller) PemDecode(publicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// pkixPublicKeyMarshaller PKIX格式公钥Marshaller
type pkixPublicKeyMarshaller struct {
}

func (*pkixPublicKeyMarshaller) Marshal(publicKey *rsa.PublicKey) (string, error) {
	pkixPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pkixPublicKey), nil
}

func (m *pkixPublicKeyMarshaller) Unmarshal(publicKey string) (*rsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	pkixPublicKey, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return pkixPublicKey.(*rsa.PublicKey), nil
}

func (m *pkixPublicKeyMarshaller) PemEncode(publicKey *rsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (m *pkixPublicKeyMarshaller) PemDecode(publicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	pkixPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pkixPublicKey.(*rsa.PublicKey), nil
}
