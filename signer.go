package security

// Signer 签名器
type Signer interface {
	Sign(data []byte) ([]byte, error)       // 签名
	Verify(data, sign []byte) (bool, error) // 验签
}
