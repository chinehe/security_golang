package security

import (
	"io"
)

// DataDigester 数据摘要
type DataDigester interface {
	BytesDigest(data []byte) string              // 字节数组Sha
	ReaderDigest(data io.Reader) (string, error) // 读取器Sha
}
