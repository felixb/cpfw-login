package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"io"
)

func encrypt(rand io.Reader, params LoginParams, password string) (string, error) {
	var b bytes.Buffer
	b.WriteString(params.LoginToken)
	b.WriteString(password)
	b.WriteByte(0x00)
	crypted, err := rsa.EncryptPKCS1v15(rand, &params.PublicKey, b.Bytes())
	if err != nil {
		return "", err
	}
	return reverse(hex.EncodeToString(crypted)), nil
}

func reverse(s string) string {
	var b bytes.Buffer
	l := len(s)
	for j := l - 2; j >= 0; j = j - 2 {
		b.WriteString(s[j : j+2])
	}
	return b.String()
}
