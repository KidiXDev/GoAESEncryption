package main

import (
	"fmt"
	"os"
	"time"

	"github.com/KidiXDev/GoAESEncryption/pkg/aes"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./GoAESEncryption.exe <filename> --encrypt or --decrypt <password>")
		fmt.Println("Press 'Enter' to exit...")
		fmt.Scanln()
		return
	}

	filename := os.Args[1]
	operation := os.Args[2]

	if operation == "--encrypt" {
		if _, err := os.Stat(filename); err != nil {
			if os.IsNotExist(err) {
				fmt.Println("File not found. Please provide a valid file for decryption.")
			} else {
				fmt.Printf("Error accessing file: %v\n", err)
			}
			fmt.Scanln()
			return
		}

		fmt.Println("Encrypting...")
		start := time.Now()
		if err := aes.EncryptFile(filename); err != nil {
			fmt.Printf("Encryption failed: %v\n", err)
			return
		}
		duration := time.Since(start)
		fmt.Printf("Encryption complete! Time taken: %.2f seconds\n", duration.Seconds())
	} else if operation == "--decrypt" {
		if len(os.Args) < 4 {
			fmt.Println("Error: Insufficient arguments.")
			fmt.Println("Usage: ./GoAESEncryption.exe <filename> --decrypt <password>")
			fmt.Println("Press 'Enter' to exit...")
			fmt.Scanln()
			return
		}
		if _, err := os.Stat(filename); err != nil {
			if os.IsNotExist(err) {
				fmt.Println("File not found. Please provide a valid file for decryption.")
			} else {
				fmt.Printf("Error accessing file: %v\n", err)
			}
			fmt.Scanln()
			return
		}
		if len(filename) < 4 || filename[len(filename)-4:] != ".enc" {
			fmt.Println("Invalid file format. Please provide a .enc file for decryption.")
			fmt.Scanln()
			return
		}
		password := os.Args[3]
		if len(password) == 0 {
			fmt.Println("Error: Password cannot be empty for decryption.")
			fmt.Println("Usage: ./GoAESEncryption.exe <filename> --decrypt <password>")
			fmt.Scanln()
			return
		}
		fmt.Println("Decrypting...")
		start := time.Now()
		if err := aes.DecryptFile(filename, password); err != nil {
			fmt.Printf("Decryption failed: %v\n", err)
			return
		}
		duration := time.Since(start)
		fmt.Printf("Decryption complete! Time taken: %.2f seconds\n", duration.Seconds())
	} else {
		fmt.Println("Unknown operation. Use --encrypt or --decrypt.")
	}
	fmt.Println("Press 'Enter' to exit...")
	fmt.Scanln()
}
