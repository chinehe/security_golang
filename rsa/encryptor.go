package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// Encryptor RSA 加解密机
type Encryptor struct {
	publicKey            *rsa.PublicKey       // 公钥
	publicKeyStr         string               // 序列化后的公钥
	publicKeyMarshaller  PublicKeyMarshaller  // 公钥序列化器
	privateKey           *rsa.PrivateKey      // 私钥
	privateKeyStr        string               // 序列化后的私钥
	privateKeyMarshaller PrivateKeyMarshaller // 私钥序列化器
}

func (e *Encryptor) Encrypt(data []byte) ([]byte, error) {
	// 优先使用公钥对象
	if e.publicKey != nil {
		return rsa.EncryptPKCS1v15(rand.Reader, e.publicKey, data)
	}
	// 使用公钥字符串
	publicKey, err := e.publicKeyMarshaller.Unmarshal(e.publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invaild public key(%s):%v", e.publicKeyStr, err)
	}
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
	// 优先使用私钥对象
	if e.privateKey != nil {
		return rsa.DecryptPKCS1v15(rand.Reader, e.privateKey, data)
	}
	// 使用私钥字符串
	privateKey, err := e.privateKeyMarshaller.Unmarshal(e.privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invaild private key(%s):%v", e.privateKeyStr, err)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}
