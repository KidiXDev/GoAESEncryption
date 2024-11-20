package main

import (
	"fmt"
	"os"
	"time"

	"github.com/KidiXDev/GoAESEncryption/pkg/aes"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./main.exe <filename> --encrypt or --decrypt <password>")
		fmt.Println("Press 'Enter' to exit...")
		fmt.Scanln()
		return
	}

	filename := os.Args[1]
	operation := os.Args[2]

	if operation == "--encrypt" {
		fmt.Println("Encrypting...")
		start := time.Now()
		if err := aes.EncryptFile(filename); err != nil {
			fmt.Printf("Encryption failed: %v\n", err)
			return
		}
		fmt.Printf("Encryption complete! Time taken: %v\n", time.Since(start))
	} else if operation == "--decrypt" {
		if len(os.Args) < 4 {
			fmt.Println("Usage: ./main.exe <filename> --decrypt <password>")
			fmt.Println("Press 'Enter' to exit...")
			fmt.Scanln()
			return
		}
		password := os.Args[3]
		if password == "" {
			fmt.Println("Password cannot be empty for decryption")
			fmt.Scanln()
			return
		}
		fmt.Println("Decrypting...")
		start := time.Now()
		if err := aes.DecryptFile(filename+".enc", password); err != nil {
			fmt.Printf("Decryption failed: %v\n", err)
			return
		}
		fmt.Printf("Decryption complete! Time taken: %v\n", time.Since(start))
	} else {
		fmt.Println("Unknown operation. Use --encrypt or --decrypt.")
	}
	fmt.Println("Press 'Enter' to exit...")
	fmt.Scanln()
}
