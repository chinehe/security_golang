package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

var (
	PrivateKeyBase64MarshallerPKCS1 = &pkcs1PrivateKeyBase64Marshaller{}
	PrivateKeyBase64MarshallerPKCS8 = &pkcs8PrivateKeyBase64Marshaller{}
	PrivateKeyPemMarshallerPKCS1    = &pkcs1PrivateKeyPemMarshaller{}
	PrivateKeyPemMarshallerPKCS8    = &pkcs8PrivateKeyPemMarshaller{}
	PublicKeyBase64MarshallerPKCS1  = &pkcs1PublicKeyBase64Marshaller{}
	PublicKeyBase64MarshallerPKIX   = &pkixPublicKeyBase64Marshaller{}
	PublicKeyPemMarshallerPKCS1     = &pkcs1PublicKeyPemMarshaller{}
	PublicKeyPemMarshallerPKIX      = &pkixPublicKeyPemMarshaller{}
)

// PrivateKeyMarshaller 私钥Marshaller接口
type PrivateKeyMarshaller interface {
	Marshal(privateKey *rsa.PrivateKey) (string, error)
	Unmarshal(privateKey string) (*rsa.PrivateKey, error)
}

// pkcs1PrivateKeyBase64Marshaller PKCS1格式私钥Marshaller
type pkcs1PrivateKeyBase64Marshaller struct {
}

func (m *pkcs1PrivateKeyBase64Marshaller) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	marshalPKCS1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	return base64.StdEncoding.EncodeToString(marshalPKCS1PrivateKey), nil
}

func (m *pkcs1PrivateKeyBase64Marshaller) Unmarshal(privateKey string) (*rsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(bytes)
}

type pkcs1PrivateKeyPemMarshaller struct {
}

func (m *pkcs1PrivateKeyPemMarshaller) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1PrivateKey,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (m *pkcs1PrivateKeyPemMarshaller) Unmarshal(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// pkcs8PrivateKeyBase64Marshaller PKCS8格式私钥Marshaller
type pkcs8PrivateKeyBase64Marshaller struct {
}

func (m *pkcs8PrivateKeyBase64Marshaller) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pkcs8PrivateKey), err
}

func (m *pkcs8PrivateKeyBase64Marshaller) Unmarshal(privateKey string) (*rsa.PrivateKey, error) {
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

type pkcs8PrivateKeyPemMarshaller struct {
}

func (m *pkcs8PrivateKeyPemMarshaller) Marshal(privateKey *rsa.PrivateKey) (string, error) {
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

func (m *pkcs8PrivateKeyPemMarshaller) Unmarshal(privateKey string) (*rsa.PrivateKey, error) {
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
}

// pkcs1PublicKeyBase64Marshaller PKCS1格式公钥Marshaller
type pkcs1PublicKeyBase64Marshaller struct {
}

func (*pkcs1PublicKeyBase64Marshaller) Marshal(publicKey *rsa.PublicKey) (string, error) {
	pkcs1PublicKey := x509.MarshalPKCS1PublicKey(publicKey)
	return base64.StdEncoding.EncodeToString(pkcs1PublicKey), nil
}

func (m *pkcs1PublicKeyBase64Marshaller) Unmarshal(publicKey string) (*rsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(bytes)
}

type pkcs1PublicKeyPemMarshaller struct {
}

func (m *pkcs1PublicKeyPemMarshaller) Marshal(publicKey *rsa.PublicKey) (string, error) {
	bytes := x509.MarshalPKCS1PublicKey(publicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (m *pkcs1PublicKeyPemMarshaller) Unmarshal(publicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// pkixPublicKeyBase64Marshaller PKIX格式公钥Marshaller
type pkixPublicKeyBase64Marshaller struct {
}

func (*pkixPublicKeyBase64Marshaller) Marshal(publicKey *rsa.PublicKey) (string, error) {
	pkixPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pkixPublicKey), nil
}

func (m *pkixPublicKeyBase64Marshaller) Unmarshal(publicKey string) (*rsa.PublicKey, error) {
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

type pkixPublicKeyPemMarshaller struct {
}

func (m *pkixPublicKeyPemMarshaller) Marshal(publicKey *rsa.PublicKey) (string, error) {
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

func (m *pkixPublicKeyPemMarshaller) Unmarshal(publicKey string) (*rsa.PublicKey, error) {
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
