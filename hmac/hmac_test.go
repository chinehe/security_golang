package hmac

import (
	"crypto/md5"
	"fmt"
	"strings"
	"testing"
)

func TestDigester(t *testing.T) {
	data := "Hello World"
	key := []byte("123456")
	fmt.Println(BytesDigester(md5.New, []byte(data), key))
	fmt.Println(ReaderDigester(md5.New, strings.NewReader(data), key))

	//fmt.Println(BytesDigester(sha1.New, []byte(data), key))
	//fmt.Println(ReaderDigester(sha1.New, strings.NewReader(data), key))
}
