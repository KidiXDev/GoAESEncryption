# GoAESEncryption

GoAESEncryption is a simple command-line tool for encrypting and decrypting files using AES encryption in Go.

## Features

- Encrypt files using AES encryption.
- Decrypt files using AES encryption.
- Automatically generates a random password and salt for encryption.
- Uses PBKDF2 for key derivation.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/KidiXDev/GoAESEncryption.git
    ```
2. Navigate to the project directory:
    ```bash
    cd GoAESEncryption
    ```
3. Build the project:
    ```bash
    go build -o GoAESEncryption cmd/app/main.go
    ```

## Usage

### Encrypt a file

To encrypt a file, use the `--encrypt` flag:
```bash
./GoAESEncryption <filename> --encrypt
```
This will generate an encrypted file with the `.enc` extension and print the password used for encryption.

### Decrypt a file

To decrypt a file, use the `--decrypt` flag followed by the password:
```bash
./GoAESEncryption <filename> --decrypt <password>
```
This will generate a decrypted file with the `dec_` prefix.

## Example

Encrypting a file:
```bash
./GoAESEncryption example.txt --encrypt
```

Decrypting a file:
```bash
./GoAESEncryption example.txt.enc --decrypt <password>
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes.

## Acknowledgements

- [Go](https://go.dev/)
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)
