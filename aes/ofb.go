package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

// OFBEncryptor 密码分组链模式AES加密机
type OFBEncryptor struct {
	Key     []byte  // AES密钥,长度只能为16, 24, or 32 bytes
	Padding Padding // 填充方式
}

func (e *OFBEncryptor) Encrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 填充
	data = e.Padding.Padding(data, blockSize)
	// 加密
	stream := cipher.NewOFB(block, e.Key[:blockSize])
	res := make([]byte, len(data))
	stream.XORKeyStream(res, data)
	return res, err
}

func (e *OFBEncryptor) Decrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 解密
	stream := cipher.NewOFB(block, e.Key[:blockSize])
	res := make([]byte, len(data))
	stream.XORKeyStream(res, data)
	// 去除填充
	res = e.Padding.UnPadding(res, blockSize)
	return res, nil
}
