# File Encryption/Decryption Tool

A command-line tool developed in C language for encrypting and decrypting files.

## Features

- **Auto-detect Mode**: Automatically determines encryption or decryption based on input file extension
  - Regular files → Encrypt to `.fds` format
  - `.fds` files → Decrypt to original files

- **Encryption Algorithm**: Password-based stream cipher encryption
  - **Selection Rationale**: 
    - Stream cipher is suitable for file encryption, supports files of any size without padding
    - No external library dependencies (such as OpenSSL), easy to compile and cross-platform
    - Simple implementation with readable code, suitable for learning and understanding encryption principles
    - Uses XOR operation, encryption and decryption use the same algorithm, achieving symmetry
  - **Technical Details**:
    - Uses stream cipher (XOR + linear congruential generator) for encryption
    - Custom key derivation function (based on password and salt, 1000 iterations of hashing)
    - Each file uses random salt (16 bytes), ensuring different encryption results for the same file
    - Keystream is generated based on key, salt, and position, ensuring each byte position has a unique keystream
  - **Note**: This is an educational/demonstration encryption scheme. For high-security requirements, it is recommended to use industry-standard encryption algorithms such as AES

## Compilation

### Prerequisites
- GCC compiler (no other library dependencies required)

### Linux/macOS
```bash
make
```

### Windows
```bash
# Using MinGW or MSYS2
gcc -Wall -Wextra -O2 -o encoder.exe encoder.c
```

### Manual Compilation
```bash
gcc -Wall -Wextra -O2 -o encoder encoder.c
```

## Usage

### Basic Usage

```bash
# Encrypt file (automatically adds .fds extension)
./encoder document.txt

# Decrypt file (automatically removes .fds extension)
./encoder document.txt.fds

# Specify output filename
./encoder input.txt output.fds
./encoder input.fds output.txt
```

### Examples

```bash
# Encrypt a text file
./encoder secret.txt
# After entering password, generates secret.txt.fds

# Decrypt file
./encoder secret.txt.fds
# After entering password, generates secret.txt
```

## File Format

`.fds` file format:
- First 16 bytes: Salt (for key derivation)
- Remaining part: Stream cipher encrypted data

## Security Notes

- Use strong passwords to ensure security
- Passwords are not stored in files
- Lost passwords cannot recover files
- Each file uses a unique salt
- **Important**: This tool uses a simplified encryption scheme suitable for general purposes. For high-security requirements, it is recommended to use industry-standard encryption algorithms such as AES

## Dependencies

- No external dependencies (only standard C library required)

## License

This project is sample code and can be freely used and modified.

