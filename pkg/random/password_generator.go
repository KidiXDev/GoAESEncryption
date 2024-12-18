package random

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

// GenerateRandomString generates a random string of the specified length.
// The generated string is prefixed with "Encrypt-" and suffixed with "-END".
//
// Parameters:
//   - length: The length of the random string to generate.
//
// Returns:
//   - A random string of the specified length with the prefix and suffix.
//   - An error if the random string generation fails.
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
