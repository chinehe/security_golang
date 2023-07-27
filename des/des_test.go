package aes

import (
	"encoding/base64"
	"security"
	"testing"
)

func TestDES(t *testing.T) {
	//base64DESKey := GenerateBase64DESKey()
	//t.Logf("key:%s\n", base64DESKey)

	key := []byte("123456781234567812345678")
	data := []byte("1234567890")

	bytes, err := (&CBCEncryptor{
		Key:     key,
		Padding: security.PKCS7Padding,
	}).Encrypt(data)
	t.Logf("CBCEncryptor:%v,err:%v", base64.StdEncoding.EncodeToString(bytes), err)

	bytes, err = (&CFBEncryptor{
		Key:     key,
		Padding: security.PKCS7Padding,
	}).Encrypt(data)
	t.Logf("CFBEncryptor:%v,err:%v", base64.StdEncoding.EncodeToString(bytes), err)

	bytes, err = (&CTREncryptor{
		Key:     key,
		Padding: security.PKCS7Padding,
	}).Encrypt(data)
	t.Logf("CTREncryptor:%v,err:%v", base64.StdEncoding.EncodeToString(bytes), err)

	bytes, err = (&ECBEncryptor{
		Key:     key,
		Padding: security.PKCS7Padding,
	}).Encrypt(data)
	t.Logf("ECBEncryptor:%v,err:%v", base64.StdEncoding.EncodeToString(bytes), err)

	bytes, err = (&OFBEncryptor{
		Key:     key,
		Padding: security.PKCS7Padding,
	}).Encrypt(data)
	t.Logf("OFBEncryptor:%v,err:%v", base64.StdEncoding.EncodeToString(bytes), err)
}
