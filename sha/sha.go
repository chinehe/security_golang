package sha

import (
	"io"
)

// DataDigester SHA数据摘要
type DataDigester interface {
	BytesDigest(data []byte) string              // 字节数组Sha
	StringDigest(data string) string             // 字符串Sha
	ReaderDigest(data io.Reader) (string, error) // 读取器Sha
}
