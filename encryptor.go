package security

// Encryptor 加解密机
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error) // 加密
	Decrypt(data []byte) ([]byte, error) // 解密
}
