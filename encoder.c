#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SALT_SIZE 16
#define BUFFER_SIZE 4096

// Simple hash function (for key derivation)
static void simple_hash(const unsigned char *data, size_t len, unsigned char *output) {
    unsigned long hash = 5381;
    size_t i;
    
    for (i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    
    // Convert hash to 32-byte key
    for (i = 0; i < 32; i++) {
        output[i] = (unsigned char)((hash >> (i % 4 * 8)) & 0xFF);
        hash = hash * 1103515245UL + 12345UL; // Linear congruential generator
    }
}

// Key derivation function (based on password and salt)
static void derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    unsigned char combined[256];
    size_t pwd_len = strlen(password);
    size_t i;
    size_t combined_len;
    
    // Ensure password length does not exceed limit
    if (pwd_len > 128) {
        pwd_len = 128;
    }
    
    // Combine password and salt
    for (i = 0; i < pwd_len; i++) {
        combined[i] = password[i];
    }
    for (i = 0; i < SALT_SIZE; i++) {
        combined[pwd_len + i] = salt[i];
    }
    combined_len = pwd_len + SALT_SIZE;
    
    // Hash multiple times to increase security
    unsigned char temp[32];
    simple_hash(combined, combined_len, temp);
    
    // Hash again to increase complexity
    for (i = 0; i < 1000; i++) {
        unsigned char new_combined[64];
        memcpy(new_combined, temp, 32);
        size_t copy_len = combined_len < 32 ? combined_len : 32;
        memcpy(new_combined + 32, combined, copy_len);
        simple_hash(new_combined, 32 + copy_len, temp);
    }
    
    memcpy(key, temp, 32);
}

// Stream cipher encryption/decryption (XOR + pseudorandom number generation)
static void stream_cipher(unsigned char *data, size_t len, const unsigned char *key, 
                          const unsigned char *iv, size_t position) {
    size_t i;
    unsigned long state = 0;
    
    // Initialize state (based on key and IV)
    for (i = 0; i < 32; i++) {
        state = (state << 8) | key[i];
    }
    for (i = 0; i < SALT_SIZE; i++) {
        state ^= ((unsigned long)iv[i] << (i % 4 * 8));
    }
    
    // Advance state to correct position based on position
    // This ensures each byte position has a unique keystream
    for (i = 0; i < position; i++) {
        state = state * 1103515245UL + 12345UL;
    }
    
    // Stream cipher encryption/decryption
    for (i = 0; i < len; i++) {
        // Linear congruential generator generates pseudorandom numbers
        state = state * 1103515245UL + 12345UL;
        unsigned char keystream_byte = (unsigned char)((state >> 16) & 0xFF);
        
        // XOR encryption/decryption
        data[i] ^= keystream_byte;
    }
}

// Generate random salt
static void generate_salt(unsigned char *salt) {
    size_t i;
    srand((unsigned int)time(NULL));
    
    for (i = 0; i < SALT_SIZE; i++) {
        salt[i] = (unsigned char)(rand() & 0xFF);
    }
}

// Encrypt file
int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in_fp, *out_fp;
    unsigned char salt[SALT_SIZE];
    unsigned char key[32];
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t total_bytes = 0;

    // Open input file
    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file %s\n", input_file);
        return 1;
    }

    // Open output file
    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file %s\n", output_file);
        fclose(in_fp);
        return 1;
    }

    // Generate random salt
    generate_salt(salt);
    
    // Derive key
    derive_key(password, salt, key);

    // Write salt to file header
    if (fwrite(salt, 1, SALT_SIZE, out_fp) != SALT_SIZE) {
        fprintf(stderr, "Error: Failed to write salt\n");
        fclose(in_fp);
        fclose(out_fp);
        return 1;
    }

    // Encrypt data
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in_fp)) > 0) {
        stream_cipher(buffer, bytes_read, key, salt, total_bytes);
        
        if (fwrite(buffer, 1, bytes_read, out_fp) != bytes_read) {
            fprintf(stderr, "Error: Failed to write file\n");
            fclose(in_fp);
            fclose(out_fp);
            return 1;
        }
        
        total_bytes += bytes_read;
    }

    fclose(in_fp);
    fclose(out_fp);

    printf("Encryption successful: %s -> %s\n", input_file, output_file);
    return 0;
}

// Decrypt file
int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in_fp, *out_fp;
    unsigned char salt[SALT_SIZE];
    unsigned char key[32];
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t total_bytes = 0;

    // Open input file
    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error: Cannot open input file %s\n", input_file);
        return 1;
    }

    // Read salt
    if (fread(salt, 1, SALT_SIZE, in_fp) != SALT_SIZE) {
        fprintf(stderr, "Error: Invalid file format (cannot read salt)\n");
        fclose(in_fp);
        return 1;
    }

    // Derive key
    derive_key(password, salt, key);

    // Open output file
    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: Cannot create output file %s\n", output_file);
        fclose(in_fp);
        return 1;
    }

    // Decrypt data
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in_fp)) > 0) {
        stream_cipher(buffer, bytes_read, key, salt, total_bytes);
        
        if (fwrite(buffer, 1, bytes_read, out_fp) != bytes_read) {
            fprintf(stderr, "Error: Failed to write file\n");
            fclose(in_fp);
            fclose(out_fp);
            return 1;
        }
        
        total_bytes += bytes_read;
    }

    fclose(in_fp);
    fclose(out_fp);

    printf("Decryption successful: %s -> %s\n", input_file, output_file);
    return 0;
}

// Check if file extension is .fds
int is_fds_file(const char *filename) {
    size_t len = strlen(filename);
    if (len < 4) return 0;
    return strcmp(filename + len - 4, ".fds") == 0;
}

// Generate output filename
char* generate_output_filename(const char *input_file, int is_encrypt) {
    char *output_file;
    size_t len = strlen(input_file);
    
    if (is_encrypt) {
        // Encryption: add .fds extension
        output_file = (char*)malloc(len + 5);
        if (!output_file) return NULL;
        strcpy(output_file, input_file);
        strcat(output_file, ".fds");
    } else {
        // Decryption: remove .fds extension
        output_file = (char*)malloc(len - 3);
        if (!output_file) return NULL;
        strncpy(output_file, input_file, len - 4);
        output_file[len - 4] = '\0';
    }
    
    return output_file;
}

int main(int argc, char *argv[]) {
    char *input_file, *output_file, *password;
    int is_encrypt;
    char password_buffer[256];

    if (argc < 2) {
        printf("Usage: %s <file_path> [output_file_path]\n", argv[0]);
        printf("\nFeatures:\n");
        printf("  - If input file is not .fds format, encrypt file and save as .fds format\n");
        printf("  - If input file is .fds format, decrypt file\n");
        printf("\nExamples:\n");
        printf("  %s document.txt          # Encrypt to document.txt.fds\n", argv[0]);
        printf("  %s document.txt.fds      # Decrypt to document.txt\n", argv[0]);
        printf("  %s file.txt output.fds   # Encrypt to output.fds\n", argv[0]);
        return 1;
    }

    input_file = argv[1];
    
    // Determine whether to encrypt or decrypt
    is_encrypt = !is_fds_file(input_file);

    // Determine output filename
    if (argc >= 3) {
        output_file = argv[2];
    } else {
        output_file = generate_output_filename(input_file, is_encrypt);
        if (!output_file) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return 1;
        }
    }

    // Get password
    printf("Enter password: ");
    fflush(stdout);
    if (fgets(password_buffer, sizeof(password_buffer), stdin) == NULL) {
        fprintf(stderr, "Error: Cannot read password\n");
        if (argc < 3) free(output_file);
        return 1;
    }
    
    // Remove newline character
    size_t pwd_len = strlen(password_buffer);
    if (pwd_len > 0 && password_buffer[pwd_len - 1] == '\n') {
        password_buffer[pwd_len - 1] = '\0';
    }
    
    if (strlen(password_buffer) == 0) {
        fprintf(stderr, "Error: Password cannot be empty\n");
        if (argc < 3) free(output_file);
        return 1;
    }
    
    password = password_buffer;

    // Execute encryption or decryption
    int result;
    if (is_encrypt) {
        result = encrypt_file(input_file, output_file, password);
    } else {
        result = decrypt_file(input_file, output_file, password);
    }

    // If output filename is dynamically generated, free memory
    if (argc < 3) {
        free(output_file);
    }

    return result;
}
