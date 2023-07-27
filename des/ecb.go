package aes

import (
	"crypto/des"
	"security"
)

// ECBEncryptor 电码本模式DES加密机
type ECBEncryptor struct {
	Key     []byte           // 密钥,长度只能为8
	Padding security.Padding // 填充方式
}

func (e *ECBEncryptor) Encrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := des.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 填充
	data = e.Padding.Padding(data, blockSize)
	// CEB是把整个明文分成若干段相同的小段，然后对每一小段进行加密
	res := make([]byte, len(data))
	for startIndex := 0; startIndex < len(data); startIndex += blockSize {
		endIndex := startIndex + blockSize
		block.Encrypt(res[startIndex:endIndex], data[startIndex:endIndex])
	}
	return res, err
}

func (e *ECBEncryptor) Decrypt(data []byte) ([]byte, error) {
	// 创建密码块
	block, err := des.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 解密
	res := make([]byte, len(data))
	for startIndex := 0; startIndex < len(data); startIndex += blockSize {
		endIndex := startIndex + blockSize
		block.Decrypt(res[startIndex:endIndex], data[startIndex:endIndex])
	}
	// 去除填充
	res = e.Padding.UnPadding(res, blockSize)
	return res, nil
}
