package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

type KeyGenerator struct {
	Bits                 int                  // 长度
	privateKeyMarshaller PrivateKeyMarshaller // 私钥序列化器
	publicKeyMarshaller  PublicKeyMarshaller  // 公钥序列化器
}

// Generate 生成RSA公私钥
func (g *KeyGenerator) Generate() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, g.Bits)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.PublicKey
	return privateKey, &publicKey, err
}

// GenerateStr 生成RSA公私钥字符串
func (g *KeyGenerator) GenerateStr() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, g.Bits)
	if err != nil {
		return "", "", err
	}
	publicKey := privateKey.PublicKey
	// 序列化
	privateKeyStr, err := g.privateKeyMarshaller.Marshal(privateKey)
	if err != nil {
		return "", "", err
	}
	publicKeyStr, err := g.publicKeyMarshaller.Marshal(&publicKey)
	if err != nil {
		return "", "", err
	}
	return privateKeyStr, publicKeyStr, err
}
