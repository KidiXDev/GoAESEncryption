package utils

import (
	"crypto/rand"
	"fmt"
)

func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	randomString := string(b)
	return fmt.Sprintf("Encrypt-%s-END", randomString), nil
}

func GenerateRandomSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}
