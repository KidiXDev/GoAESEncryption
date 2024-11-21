package utils

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const charsetLen = byte(len(charset))

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func GenerateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}

	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	buffer.Grow(length + 11)

	buffer.WriteString("Encrypt-")
	for i := range b {
		buffer.WriteByte(charset[b[i]%charsetLen])
	}
	buffer.WriteString("-END")

	result := buffer.String()
	bufferPool.Put(buffer)
	return result, nil
}

func GenerateRandomSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}
