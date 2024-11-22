package utils

import (
	"crypto/rand"
	"fmt"
)

// GenerateRandomSalt generates a random salt of 32 bytes.
//
// Returns:
//   - A byte slice containing the random salt.
//   - An error if the random salt generation fails.
func GenerateRandomSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}
