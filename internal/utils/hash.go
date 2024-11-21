package utils

import (
	"bytes"
	"crypto/sha256"
)

func HashPassword(password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	return h.Sum(nil)
}

func ValidatePassword(inputPassword string, savedHash []byte) bool {
	inputHash := HashPassword(inputPassword)
	return bytes.Equal(inputHash, savedHash)
}
