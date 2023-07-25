package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"security"
)

// CTREncryptor 密码分组链模式AES加密机
type CTREncryptor struct {
	Key     []byte           // AES密钥,长度只能为16, 24, or 32 bytes
	Padding security.Padding // 填充方式
}

func (e *CTREncryptor) Encrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 填充
	data = e.Padding.Padding(data, blockSize)
	// 加密
	stream := cipher.NewCTR(block, e.Key[:blockSize])
	res := make([]byte, len(data))
	stream.XORKeyStream(res, data)
	return res, err
}

func (e *CTREncryptor) Decrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 解密
	stream := cipher.NewCTR(block, e.Key[:blockSize])
	res := make([]byte, len(data))
	stream.XORKeyStream(res, data)
	// 去除填充
	res = e.Padding.UnPadding(res, blockSize)
	return res, nil
}
