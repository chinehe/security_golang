package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"security"
)

type Signer struct {
	PublicKey            *rsa.PublicKey        // 公钥
	PublicKeyStr         string                // 序列化后的公钥
	PublicKeyMarshaller  PublicKeyMarshaller   // 公钥序列化器
	PrivateKey           *rsa.PrivateKey       // 私钥
	PrivateKeyStr        string                // 序列化后的私钥
	PrivateKeyMarshaller PrivateKeyMarshaller  // 私钥序列化器
	DataDigester         security.DataDigester // 数据摘要器
	Hash                 crypto.Hash           // hash
}

func (s *Signer) Sign(data []byte) (sign []byte, err error) {
	// 私钥
	var privateKey *rsa.PrivateKey
	if s.PrivateKey != nil {
		privateKey = s.PrivateKey
	} else {
		privateKey, err = s.PrivateKeyMarshaller.Unmarshal(s.PrivateKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid private key(%s):%v", s.PrivateKeyStr, err)
		}
	}
	digest := s.DataDigester.BytesDigest(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, s.Hash, []byte(digest))
}

func (s *Signer) Verify(data, sign []byte) (err error) {
	// 公钥
	var publicKey *rsa.PublicKey
	if s.PublicKey != nil {
		publicKey = s.PublicKey
	} else {
		publicKey, err = s.PublicKeyMarshaller.Unmarshal(s.PublicKeyStr)
		if err != nil {
			return fmt.Errorf("invalid public key(%s):%v", s.PublicKeyStr, err)
		}
	}
	digest := s.DataDigester.BytesDigest(data)
	return rsa.VerifyPKCS1v15(publicKey, s.Hash, []byte(digest), sign)
}
