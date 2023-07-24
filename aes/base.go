package aes

// Encryptor AES加密机
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error) // 加密
	Decrypt(data []byte) ([]byte, error) // 解密
}

// Padding 填充机
type Padding interface {
	Padding(ori []byte, blockSize int) []byte
	UnPadding(ori []byte, blockSize int) []byte
}
