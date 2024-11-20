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

	"golang.org/x/crypto/pbkdf2"
)

const keySize = 32

// EncryptFile encrypts the contents of the specified file using AES encryption
// in CTR mode. It generates a random salt and password, derives an encryption
// key using PBKDF2, and writes the IV and salt to the beginning of the output
// file. The encrypted data is written to a new file with the same name as the
// original file but with an ".enc" extension.
//
// Parameters:
//   - filename: The path to the file to be encrypted.
//
// Returns:
//   - error: An error if any step of the encryption process fails, otherwise nil.
func EncryptFile(filename string) error {
	srcFile, err := os.Open(filename)
	if err := utils.CheckErr("failed to open source file", err); err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(filename + ".enc")
	if err := utils.CheckErr("failed to create destination file", err); err != nil {
		return err
	}
	defer destFile.Close()

	salt, err := utils.GenerateRandomSalt()
	if err := utils.CheckErr("salt generation failed", err); err != nil {
		return err
	}
	str, err := utils.GenerateRandomString(256)
	if err := utils.CheckErr("password generation failed", err); err != nil {
		return err
	}
	key, err := pbkdf2Key([]byte(str), salt)
	if err := utils.CheckErr("key generation failed", err); err != nil {
		return err
	}

	fmt.Println("Password:", str)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return utils.CheckErr("failed to generate IV", err)
	}

	if _, err := destFile.Write(iv); err != nil {
		if err := utils.CheckErr("failed to write IV", err); err != nil {
			return err
		}
	}

	if _, err := destFile.Write(salt); err != nil {
		if err := utils.CheckErr("failed to write salt", err); err != nil {
			return err
		}
	}

	block, err := aes.NewCipher(key)
	if err := utils.CheckErr("failed to create cipher block", err); err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	buf := make([]byte, 1*1024*1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return utils.CheckErr("failed to read source file", err)
		}
		if n == 0 {
			break
		}

		stream.XORKeyStream(buf[:n], buf[:n])

		if _, err := destFile.Write(buf[:n]); err != nil {
			if err := utils.CheckErr("failed to write to destination file", err); err != nil {
				return err
			}
		}
	}

	return nil
}

// DecryptFile decrypts an encrypted file using the provided password.
// The decrypted content is written to a new file with the prefix "dec_" added to the original filename.
//
// Parameters:
//   - filename: The path to the encrypted file to be decrypted.
//   - password: The password used to decrypt the file.
//
// Returns:
//   - error: An error if any occurs during the decryption process, otherwise nil.
//
// The decryption process involves:
//  1. Opening the source encrypted file.
//  2. Creating a destination file for the decrypted content.
//  3. Reading the initialization vector (IV) and salt from the source file.
//  4. Deriving the encryption key using PBKDF2 with the provided password and salt.
//  5. Creating an AES cipher block and a CTR stream for decryption.
//  6. Reading the encrypted content in chunks, decrypting it, and writing it to the destination file.
func DecryptFile(filename string, password string) error {
	srcFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	destFilename := filename[:len(filename)-4]
	destFilename = "dec_" + destFilename
	destFile, err := os.Create(destFilename)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(srcFile, iv); err != nil {
		return fmt.Errorf("failed to read IV: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(srcFile, salt); err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
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
