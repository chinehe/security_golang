package aes

import (
	"crypto/cipher"
	"crypto/des"
	"security"
)

// CBCEncryptor 密码分组链模式DES加密机
type CBCEncryptor struct {
	Key     []byte           // 密钥,长度只能8
	Padding security.Padding // 填充方式
}

func (e *CBCEncryptor) Encrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := des.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 填充
	data = e.Padding.Padding(data, blockSize)
	// 加密
	blockMode := cipher.NewCBCEncrypter(block, e.Key[:blockSize])
	res := make([]byte, len(data))
	blockMode.CryptBlocks(res, data)
	return res, err
}

func (e *CBCEncryptor) Decrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := des.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 解密
	res := make([]byte, len(data))
	blockMode := cipher.NewCBCDecrypter(block, e.Key[:blockSize])
	blockMode.CryptBlocks(res, data)
	// 去除填充
	res = e.Padding.UnPadding(res, blockSize)
	return res, nil
}
