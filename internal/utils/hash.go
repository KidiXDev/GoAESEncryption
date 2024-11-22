package utils

import (
	"bytes"
	"crypto/sha256"
)

// HashPassword hashes the input password using SHA-256.
// It returns the hashed password as a byte slice.
func HashPassword(password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	return h.Sum(nil)
}

// ValidatePassword compares the input password with the saved hash.
// It returns true if the passwords match, false otherwise.
func ValidatePassword(inputPassword string, savedHash []byte) bool {
	inputHash := HashPassword(inputPassword)
	return bytes.Equal(inputHash, savedHash)
}
