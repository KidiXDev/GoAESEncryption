package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/KidiXDev/GoAESEncryption/internal/utils"
	"github.com/KidiXDev/GoAESEncryption/pkg/random"

	"golang.org/x/crypto/pbkdf2"
)

const keySize = 32 // 32 bytes = 256 bits

// EncryptFile encrypts the contents of the specified file using AES encryption
// in CTR mode. It generates a random salt and password, derives an encryption
// key using PBKDF2, and writes the IV and salt to the beginning of the output
// file. The encrypted data is written to a new file with the same name as the
// original file but with an ".enc" extension.
//
// Parameters:
//   - filename: The path to the file to be encrypted.
//   - pass: A pointer use for the password used for encryption. If nil, a random password will be generated.
//
// Returns:
//   - string: The password used for encryption.
//   - error: An error if any step of the encryption process fails, otherwise nil.
func EncryptFile(filename string, pass *string) (string, error) {
	srcFile, err := os.Open(filename)
	if err := utils.CheckErr("failed to open source file", err); err != nil {
		return "", err
	}
	defer func(srcFile *os.File) {
		_ = srcFile.Close()
	}(srcFile)

	destFile, err := os.Create(filename + ".enc") // Append .enc to the filename
	if err := utils.CheckErr("failed to create destination file", err); err != nil {
		return "", err
	}
	defer func(destFile *os.File) {
		_ = destFile.Close()
	}(destFile)

	salt, err := utils.GenerateRandomSalt() // Generate a random 256-bit salt
	if err := utils.CheckErr("salt generation failed", err); err != nil {
		return "", err
	}

	// Generate a random password if none is provided
	if pass == nil {
		fmt.Println("Generating random password...")
		generatedPass, err := random.GenerateRandomString(256)
		if err := utils.CheckErr("password generation failed", err); err != nil {
			return "", err
		}
		pass = &generatedPass
	}

	key, err := pbkdf2Key([]byte(*pass), salt) // Create the 256-bit key using PBKDF2 based on the password and salt
	if err := utils.CheckErr("key generation failed", err); err != nil {
		return "", err
	}

	fmt.Println("Password:", *pass)

	// Save the password hash to validate during decryption
	passwordHash := utils.HashPassword(*pass) // Hash password for later validation
	if _, err := destFile.Write(passwordHash); err != nil {
		return "", utils.CheckErr("failed to write password hash", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", utils.CheckErr("failed to generate IV", err)
	}

	if _, err := destFile.Write(iv); err != nil {
		return "", utils.CheckErr("failed to write IV", err)
	}

	if _, err := destFile.Write(salt); err != nil {
		return "", utils.CheckErr("failed to write salt", err)
	}

	block, err := aes.NewCipher(key)
	if err := utils.CheckErr("failed to create cipher block", err); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)

	buf := make([]byte, 1*1024*1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", utils.CheckErr("failed to read source file", err)
		}
		if n == 0 {
			break
		}

		stream.XORKeyStream(buf[:n], buf[:n])

		if _, err := destFile.Write(buf[:n]); err != nil {
			return "", utils.CheckErr("failed to write to destination file", err)
		}
	}

	return *pass, nil
}

// DecryptFile decrypts an encrypted file using the provided password.
// The decrypted content is saved to a new file with a "dec_" prefix added to the original filename.
//
// Parameters:
//   - filename: The path to the encrypted file.
//   - password: The password used for decryption.
//
// Returns:
//   - error: An error if the decryption process fails, otherwise nil.
//
// The function performs the following steps:
//  1. Opens the encrypted file for reading.
//  2. Creates a new file for writing the decrypted content.
//  3. Reads the saved password hash, IV, and salt from the encrypted file.
//  4. Validates the provided password against the saved password hash.
//  5. Generates a decryption key using PBKDF2 with the provided password and salt.
//  6. Creates a new AES cipher block and a CTR stream for decryption.
//  7. Reads the encrypted content in chunks, decrypts it, and writes the decrypted content to the new file.
//
// If the password is invalid, the function deletes the partially created destination file and returns an error.
func DecryptFile(filename string, password string) error {
	srcFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}

	defer func(srcFile *os.File) {
		_ = srcFile.Close()
	}(srcFile)

	destFilename := filename[:len(filename)-4]
	destFilename = "dec_" + destFilename
	destFile, err := os.Create(destFilename)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func(destFile *os.File) {
		_ = destFile.Close()
	}(destFile)

	// Read the saved password hash from the encrypted file
	savedPasswordHash := make([]byte, sha256.Size)
	if _, err := io.ReadFull(srcFile, savedPasswordHash); err != nil {
		return fmt.Errorf("failed to read saved password hash: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(srcFile, iv); err != nil {
		return fmt.Errorf("failed to read IV: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(srcFile, salt); err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}

	// Validate the password by checking the hash
	if !utils.ValidatePassword(password, savedPasswordHash) {
		// delete the destination file if the password is invalid
		if err := destFile.Close(); err != nil {
			return fmt.Errorf("failed to close destination file: %w", err)
		}
		if err := srcFile.Close(); err != nil {
			return fmt.Errorf("failed to close source file: %w", err)
		}
		if err := os.Remove(destFilename); err != nil {
			return fmt.Errorf("failed to delete destination file: %w", err)
		}
		return fmt.Errorf("invalid password")
	}

	key, err := pbkdf2Key([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("key generation failed: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	stream := cipher.NewCTR(block, iv)

	buf := make([]byte, 1*1024*1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read source file: %w", err)
		}
		if n == 0 {
			break
		}

		stream.XORKeyStream(buf[:n], buf[:n])

		if _, err := destFile.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write to destination file: %w", err)
		}
	}

	return nil
}

func pbkdf2Key(password, salt []byte) ([]byte, error) {
	return pbkdf2.Key(password, salt, 4096, keySize, sha256.New), nil
}
