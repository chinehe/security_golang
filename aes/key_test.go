package aes

import (
	"testing"
)

func TestGenerateAESKey(t *testing.T) {
	t.Log(GenerateBase64AESKey(16))
	t.Log(GenerateBase64AESKey(24))
	t.Log(GenerateBase64AESKey(32))
}
