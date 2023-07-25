package security

import (
	"bytes"
)

var (
	NoPadding    = &noPadding{}    // 不填充，只能加密128bits倍数的数据，一般不使用
	PKCS7Padding = &pkcs7Padding{} // PKCS#7填充
)

// Padding 填充机
type Padding interface {
	Padding(ori []byte, blockSize int) []byte
	UnPadding(ori []byte, blockSize int) []byte
}

// noPadding 不填充，只能加密128bits倍数的数据，一般不使用
type noPadding struct {
}

func (p *noPadding) Padding(ori []byte, blockSize int) []byte {
	return ori
}

func (p *noPadding) UnPadding(ori []byte, blockSize int) []byte {
	return ori
}

// pkcs7Padding PKCS#7填充
type pkcs7Padding struct {
}

func (p *pkcs7Padding) Padding(ori []byte, blockSize int) []byte {
	// 要填充的长度
	paddingLen := blockSize - len(ori)%blockSize
	// 填充的数据
	paddingBytes := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	// 填充
	return append(ori, paddingBytes...)
}

func (p *pkcs7Padding) UnPadding(ori []byte, blockSize int) []byte {
	oriLen := len(ori)
	paddingLen := int(ori[oriLen-1])
	return ori[:oriLen-paddingLen]
}
