#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#define INPUT_BLOCK 64 // Define the block size for processing
#define INPUT_BLOCK_LENGTH 15

#define MESSAGE_CHUNK 200

// -------------------------------------------   HASH   ---------------------------------------------

void compute_sha1_hash(const char* filename, unsigned char* finalDigest) {
    //const char* filename = "D:\\C\\Refactored_Hash\\demo.txt";
    //unsigned char finalDigest[SHA_DIGEST_LENGTH];
    //compute_sha1_hash(filename, finalDigest);
    FILE* f = NULL;
    errno_t err;
    SHA_CTX ctx;

    SHA1_Init(&ctx); // Initialize SHA1 context

    err = fopen_s(&f, filename, "rb");
    if (err != 0) {
        printf("Error opening the file\n");
        return;
    }

    unsigned char* tmpBuffer_Chunk = (unsigned char*)malloc(MESSAGE_CHUNK);
    if (!tmpBuffer_Chunk) {
        printf("Memory allocation failed\n");
        fclose(f);
        return;
    }

    size_t read_length = MESSAGE_CHUNK;
    while ((read_length = fread(tmpBuffer_Chunk, 1, MESSAGE_CHUNK, f)) > 0) {
        SHA1_Update(&ctx, tmpBuffer_Chunk, read_length);
    }

    free(tmpBuffer_Chunk);
    fclose(f);

    SHA1_Final(finalDigest, &ctx); // Finalize SHA1 hash
}

unsigned char* computeSHA1(const unsigned char* input, size_t input_size) {
    int remaining = input_size;
    int offset = 0;
    int read = INPUT_BLOCK;
    unsigned char* digest = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
    if (!digest) {
        return NULL; // Handle memory allocation failure
    }

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    while (remaining > 0) {
        if (remaining < INPUT_BLOCK) {
            read = remaining;
        }
        SHA1_Update(&ctx, (input + offset), read);
        remaining -= read;
        offset += read;
    }

    SHA1_Final(digest, &ctx);
    return digest;
}

int computeSHA1FromHexFile(const char* filepath, unsigned char* digest) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        perror("Failed to open file");
        return -1; // Return error code
    }

    // Determine the file size
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f); // Total length of the file
    fseek(f, 0, SEEK_SET);

    SHA_CTX context;
    SHA1_Init(&context);

    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char hex_pair[2];

    while (remaining_length > 0) {
        unsigned int read_length = (remaining_length > (INPUT_BLOCK_LENGTH * 2)) ? INPUT_BLOCK_LENGTH : (remaining_length / 2);

        for (unsigned int i = 0; i < read_length; i++) {
            if (fread(hex_pair, sizeof(unsigned char), 2, f) != 2) {
                fclose(f);
                return -1; // Handle file read error
            }
            input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
        }

        SHA1_Update(&context, input, read_length);
        remaining_length -= (read_length * 2); // Update remaining length (double for hex text representation)
    }

    fclose(f);

    SHA1_Final(digest, &context);
    return 0; // Success
}

// ------------------------------------------  WORKING WITH FILES -------------------------------
 
// read file line by line
/*

int main()
{
    // Create a file pointer and open the file "GFG.txt" in
    // read mode.
    FILE* file = fopen("GFG.txt", "r");

    // Buffer to store each line of the file.
    char line[256];

    // Check if the file was opened successfully.
    if (file != NULL) {
        // Read each line from the file and store it in the
        // 'line' buffer.
        while (fgets(line, sizeof(line), file)) {
            // Print each line to the standard output.
            printf("%s", line);
        }

        // Close the file stream once all lines have been
        // read.
        fclose(file);
    }
    else {
        // Print an error message to the standard error
        // stream if the file cannot be opened.
        fprintf(stderr, "Unable to open file!\n");
    }

    return 0;
}

*/


 long get_file_size(const char* file_path) {
if (file_path == NULL) {
    fprintf(stderr, "Error: Invalid file path.\n");
    return -1;
}

FILE* file = fopen(file_path, "rb");
if (file == NULL) {
    perror("Failed to open file");
    return -1;
}

// Move to the end of the file
if (fseek(file, 0, SEEK_END) != 0) {
    perror("Failed to seek to end of file");
    fclose(file);
    return -1;
}

// Get the file size
long file_size = ftell(file);
if (file_size < 0) {
    perror("Failed to determine file size");
    fclose(file);
    return -1;
}

// Move back to the beginning of the file (optional, but good practice)
fseek(file, 0, SEEK_SET);

fclose(file);
return file_size;
}

int write_buffer_to_file(const unsigned char* buffer, size_t size, const char* file_path) {
    if (buffer == NULL || file_path == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return -1;
    }

    FILE* file = fopen(file_path, "wb");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    size_t bytes_written = fwrite(buffer, 1, size, file);
    if (bytes_written != size) {
        perror("Failed to write to file");
        fclose(file);
        return -1;
    }

    fclose(file);
    printf("Successfully wrote %zu bytes to %s\n", bytes_written, file_path);
    return 0;
}

/**
 * Writes an unsigned char buffer to a file as ASCII.
 *
 * @param buffer     Pointer to the buffer to write.
 * @param size       Size of the buffer in bytes.
 * @param file_path  Path to the file where the buffer will be written.
 * @return           0 on success, -1 on failure.
 */
int write_buffer_to_file_ascii(const unsigned char* buffer, size_t size, const char* file_path) {
    if (buffer == NULL || file_path == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return -1;
    }

    FILE* file = fopen(file_path, "w");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    for (size_t i = 0; i < size; i++) {
        if (fputc(buffer[i], file) == EOF) {
            perror("Failed to write to file");
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    printf("Successfully wrote %zu bytes to %s as ASCII\n", size, file_path);
    return 0;
}

int read_file_to_buffer(unsigned char* buffer, size_t size, const char* file_path) {
    if (buffer == NULL || file_path == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return -1;
    }

    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, size, file);
    if (bytes_read != size) {
        if (feof(file)) {
            printf("Reached end of file. Read %zu bytes from %s\n", bytes_read, file_path);
        }
        else if (ferror(file)) {
            perror("Failed to read from file");
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    printf("Successfully read %zu bytes from %s\n", bytes_read, file_path);
    return 0;
}

int write_buffer_as_hex_to_file(const unsigned char* buffer, size_t size, const char* file_path) {
    if (buffer == NULL || file_path == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return -1;
    }

    FILE* file = fopen(file_path, "w");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    for (size_t i = 0; i < size; i++) {
        fprintf(file, "%02X ", buffer[i]); // Write each byte as a 2-digit hex value
        if ((i + 1) % 16 == 0) {          // Add a newline every 16 bytes for readability
            fprintf(file, "\n");
        }
    }

    fclose(file);
    printf("Successfully wrote %zu bytes as hex to %s\n", size, file_path);
    return 0;
}

unsigned char* read_hex_from_file(const char* file_path, size_t* size) {
    if (file_path == NULL || size == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return NULL;
    }

    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Error: File is empty or invalid.\n");
        fclose(file);
        return NULL;
    }

    // Allocate memory for the file content
    char* file_content = (char*)malloc(file_size + 1);
    if (file_content == NULL) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    // Read the entire file into memory
    size_t bytes_read = fread(file_content, 1, file_size, file);
    file_content[bytes_read] = '\0'; // Null-terminate the string

    fclose(file);

    // Count the number of hex values in the file
    size_t hex_count = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        if (isxdigit(file_content[i]) && isxdigit(file_content[i + 1])) {
            hex_count++;
            i++; // Skip the second hex digit
        }
    }

    if (hex_count == 0) {
        fprintf(stderr, "Error: No valid hex data found in the file.\n");
        free(file_content);
        return NULL;
    }

    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(hex_count);
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        free(file_content);
        return NULL;
    }

    // Parse the hex values into the buffer
    size_t buffer_index = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        if (isxdigit(file_content[i]) && isxdigit(file_content[i + 1])) {
            char hex[3] = { file_content[i], file_content[i + 1], '\0' };
            buffer[buffer_index++] = (unsigned char)strtol(hex, NULL, 16);
            i++; // Skip the second hex digit
        }
    }

    free(file_content);
    *size = hex_count; // Set the size of the buffer
    return buffer;
}

// ------------------------------------------------- AES ---------------------------------------------

/**
 * Decrypts a file using AES-ECB mode.
 *
 * @param file_path Path to the file to decrypt.
 * @param key_128   The 128-bit AES key for decryption.
 * @param output_size Pointer to store the size of the decrypted data.
 * @return Pointer to the decrypted data (dynamically allocated). Caller must free it.
 *         Returns NULL on failure.
 */
unsigned char* aes_ecb_decrypt_file(const char* file_path, const unsigned char* key_128, size_t* output_size) {
    FILE* f = NULL;
    unsigned char* plaintext = NULL;
    unsigned char* tmpBuffer_Chunk = NULL;
    unsigned char* restore = NULL;
    unsigned char* ciphertext = NULL;

    f = fopen(file_path, "rb");
    if (f == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    // Get the file size
    fseek(f, 0, SEEK_END);
    size_t remaining_length = ftell(f); // Total length of the file
    fseek(f, 0, SEEK_SET);

    // Allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(remaining_length);
    if (plaintext == NULL) {
        perror("Failed to allocate memory for plaintext");
        fclose(f);
        return NULL;
    }

    // Read the file in chunks of 15 bytes
    tmpBuffer_Chunk = (unsigned char*)malloc(15);
    if (tmpBuffer_Chunk == NULL) {
        perror("Failed to allocate memory for temporary buffer");
        free(plaintext);
        fclose(f);
        return NULL;
    }

    size_t i = 0;
    size_t read_length = 15;
    while (read_length == 15) {
        read_length = fread(tmpBuffer_Chunk, 1, 15, f);
        memcpy((plaintext + i), tmpBuffer_Chunk, read_length);
        i += read_length;
    }

    free(tmpBuffer_Chunk);
    fclose(f);

    // Set up AES key for decryption
    AES_KEY aes_key;
    AES_set_decrypt_key(key_128, 128, &aes_key);

    // Compute the size of the decrypted data
    size_t plaintext_size = remaining_length;
    unsigned char partial_block = plaintext_size % AES_BLOCK_SIZE ? 1 : 0;
    size_t ciphertext_blocks = plaintext_size / AES_BLOCK_SIZE + partial_block;

    // Allocate memory for the decrypted data
    restore = (unsigned char*)malloc(plaintext_size);
    if (restore == NULL) {
        perror("Failed to allocate memory for decrypted data");
        free(plaintext);
        return NULL;
    }

    // Perform AES-ECB decryption
    size_t cipher_block_offset = 0;
    for (cipher_block_offset = 0; cipher_block_offset < (ciphertext_blocks - 1) * AES_BLOCK_SIZE; cipher_block_offset += AES_BLOCK_SIZE) {
        AES_decrypt((plaintext + cipher_block_offset), (restore + cipher_block_offset), &aes_key);
    }

    // Handle the last block
    unsigned char temp[AES_BLOCK_SIZE];
    AES_decrypt((plaintext + cipher_block_offset), temp, &aes_key);
    if (partial_block) {
        // The last block is partial
        size_t keeping_bytes = plaintext_size % AES_BLOCK_SIZE;
        memcpy(restore + plaintext_size - keeping_bytes, temp, keeping_bytes);
    }
    else {
        // The last block is full
        memcpy(restore + plaintext_size - AES_BLOCK_SIZE, temp, AES_BLOCK_SIZE);
    }

    // Clean up
    free(plaintext);

    // Set the output size
    *output_size = plaintext_size;

    return restore;
}

unsigned char* aes_ecb_encrypt_file_no_padding(const char* file_path, const unsigned char* key_128, size_t* output_size) {
    FILE* f = NULL;
    unsigned char* plaintext = NULL;
    unsigned char* tmpBuffer_Chunk = NULL;
    unsigned char* ciphertext = NULL;

    f = fopen(file_path, "rb");
    if (f == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    // Get the file size
    fseek(f, 0, SEEK_END);
    size_t plaintext_size = ftell(f); // Total length of the file
    fseek(f, 0, SEEK_SET);

    // Increase plaintext_size to the next multiple of AES_BLOCK_SIZE if necessary
    size_t padded_size = plaintext_size;
    if (plaintext_size % AES_BLOCK_SIZE != 0) {
        padded_size = plaintext_size + (AES_BLOCK_SIZE - (plaintext_size % AES_BLOCK_SIZE));
    }

    // Allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(padded_size);
    if (plaintext == NULL) {
        perror("Failed to allocate memory for plaintext");
        fclose(f);
        return NULL;
    }

    // Initialize the extra bytes (if any) to zero
    if (padded_size > plaintext_size) {
        memset(plaintext + plaintext_size, 0, padded_size - plaintext_size);
    }

    // Read the file in chunks of 15 bytes
    tmpBuffer_Chunk = (unsigned char*)malloc(15);
    if (tmpBuffer_Chunk == NULL) {
        perror("Failed to allocate memory for temporary buffer");
        free(plaintext);
        fclose(f);
        return NULL;
    }

    size_t i = 0;
    size_t read_length = 15;
    while (read_length == 15) {
        read_length = fread(tmpBuffer_Chunk, 1, 15, f);
        memcpy((plaintext + i), tmpBuffer_Chunk, read_length);
        i += read_length;
    }

    free(tmpBuffer_Chunk);
    fclose(f);

    // Set up AES key for encryption
    AES_KEY aes_key;
    AES_set_encrypt_key(key_128, 128, &aes_key);

    // Allocate memory for the ciphertext
    ciphertext = (unsigned char*)malloc(padded_size);
    if (ciphertext == NULL) {
        perror("Failed to allocate memory for ciphertext");
        free(plaintext);
        return NULL;
    }

    // Perform AES-ECB encryption
    for (size_t block_offset = 0; block_offset < padded_size; block_offset += AES_BLOCK_SIZE) {
        AES_encrypt(plaintext + block_offset, ciphertext + block_offset, &aes_key);
    }

    // Clean up
    free(plaintext);

    // Set the output size
    *output_size = padded_size;

    return ciphertext;
}

unsigned char* aes_ecb_encrypt_buffer(const unsigned char* input_buffer, size_t input_size, const unsigned char* key_128, size_t* output_size) {
    if (input_buffer == NULL || key_128 == NULL || output_size == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return NULL;
    }

    // Set up AES key for encryption
    AES_KEY aes_key;
    AES_set_encrypt_key(key_128, 128, &aes_key);

    // Compute the size of the encrypted data
    size_t padding_length = AES_BLOCK_SIZE - (input_size % AES_BLOCK_SIZE);
    size_t padded_size = input_size + padding_length;

    // Allocate memory for the padded plaintext
    unsigned char* padded_plaintext = (unsigned char*)malloc(padded_size);
    if (padded_plaintext == NULL) {
        perror("Failed to allocate memory for padded plaintext");
        return NULL;
    }

    // Copy the input buffer and add padding
    memcpy(padded_plaintext, input_buffer, input_size);
    memset(padded_plaintext + input_size, padding_length, padding_length);

    // Allocate memory for the ciphertext
    unsigned char* ciphertext = (unsigned char*)malloc(padded_size);
    if (ciphertext == NULL) {
        perror("Failed to allocate memory for ciphertext");
        free(padded_plaintext);
        return NULL;
    }

    // Perform AES-ECB encryption
    for (size_t i = 0; i < padded_size; i += AES_BLOCK_SIZE) {
        AES_encrypt(padded_plaintext + i, ciphertext + i, &aes_key);
    }

    // Clean up
    free(padded_plaintext);

    // Set the output size
    *output_size = padded_size;

    return ciphertext;
}

unsigned char* aes_ecb_decrypt_buffer(const unsigned char* input_buffer, size_t input_size, const unsigned char* key_128, size_t* output_size) {
    if (input_buffer == NULL || key_128 == NULL || output_size == NULL) {
        fprintf(stderr, "Error: Invalid input parameters.\n");
        return NULL;
    }

    // Ensure the input size is a multiple of the AES block size
    if (input_size % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Input size must be a multiple of AES block size (%d bytes).\n", AES_BLOCK_SIZE);
        return NULL;
    }

    // Set up AES key for decryption
    AES_KEY aes_key;
    AES_set_decrypt_key(key_128, 128, &aes_key);

    // Allocate memory for the decrypted data
    unsigned char* decrypted_data = (unsigned char*)malloc(input_size);
    if (decrypted_data == NULL) {
        perror("Failed to allocate memory for decrypted data");
        return NULL;
    }

    // Perform AES-ECB decryption
    for (size_t i = 0; i < input_size; i += AES_BLOCK_SIZE) {
        AES_decrypt(input_buffer + i, decrypted_data + i, &aes_key);
    }

    // Remove PKCS7 padding
    size_t padding_length = decrypted_data[input_size - 1];
    if (padding_length > AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Invalid padding length.\n");
        free(decrypted_data);
        return NULL;
    }

    size_t plaintext_size = input_size - padding_length;
    unsigned char* plaintext = (unsigned char*)malloc(plaintext_size);
    if (plaintext == NULL) {
        perror("Failed to allocate memory for plaintext");
        free(decrypted_data);
        return NULL;
    }

    // Copy the decrypted data without padding
    memcpy(plaintext, decrypted_data, plaintext_size);

    // Clean up
    free(decrypted_data);

    // Set the output size
    *output_size = plaintext_size;

    return plaintext;
}

// ------------------------------------- RSA ----------------------------------------


int verify_signature(const char* public_key_file, const char* signature_file, const char* original_file) {
    RSA* rsa_public = NULL;
    FILE* fpublic = NULL;
    FILE* fsign = NULL;
    FILE* foriginal = NULL;
    unsigned char* rsa_signature = NULL;
    unsigned char message_digest_sha1[SHA_DIGEST_LENGTH];
    unsigned char original_digest[SHA_DIGEST_LENGTH];
    int result = -1;

    // Open the public key file
    fpublic = fopen(public_key_file, "r");
    if (!fpublic) {
        perror("Failed to open public key file");
        goto cleanup;
    }

    // Read the public key
    rsa_public = PEM_read_RSAPublicKey(fpublic, NULL, NULL, NULL);
    if (!rsa_public) {
        fprintf(stderr, "Failed to read public key\n");
        goto cleanup;
    }

    // Open the signature file
    fsign = fopen(signature_file, "rb");
    if (!fsign) {
        perror("Failed to open signature file");
        goto cleanup;
    }

    // Determine the length of the signature
    fseek(fsign, 0, SEEK_END);
    unsigned int sign_length = ftell(fsign);
    fseek(fsign, 0, SEEK_SET);

    // Allocate memory for the signature
    rsa_signature = (unsigned char*)malloc(sign_length);
    if (!rsa_signature) {
        perror("Failed to allocate memory for signature");
        goto cleanup;
    }

    // Read the signature
    if (fread(rsa_signature, 1, sign_length, fsign) != sign_length) {
        perror("Failed to read signature");
        goto cleanup;
    }

    // Open the original file
    foriginal = fopen(original_file, "rb");
    if (!foriginal) {
        perror("Failed to open original file");
        goto cleanup;
    }

    // Compute the SHA1 hash of the original file
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), foriginal)) > 0) {
        SHA1_Update(&sha_ctx, buffer, bytes_read);
    }
    SHA1_Final(original_digest, &sha_ctx);

    // Decrypt the signature using the public key
    if (RSA_public_decrypt(sign_length, rsa_signature, message_digest_sha1, rsa_public, RSA_PKCS1_PADDING) == -1) {
        fprintf(stderr, "Failed to decrypt signature\n");
        goto cleanup;
    }

    // Compare the decrypted signature with the computed hash
    result = memcmp(message_digest_sha1, original_digest, SHA_DIGEST_LENGTH);

    if (result) {
        printf("Wrong signature!\n");
    } else {
        printf("Signature has been verified!\n");
    }

cleanup:
    if (rsa_public) RSA_free(rsa_public);
    if (fpublic) fclose(fpublic);
    if (fsign) fclose(fsign);
    if (foriginal) fclose(foriginal);
    if (rsa_signature) free(rsa_signature);

    return result;
}



int sign_file(const char* file_to_be_signed, const char* private_key_file) {
    RSA* rsa_private = NULL;
    FILE* fprivate = NULL;
    FILE* fdata = NULL;
    FILE* fsign = NULL;
    unsigned char* rsa_signature = NULL;
    unsigned char hash[SHA_DIGEST_LENGTH]; // SHA-1 produces a 20-byte hash

    // Open the file to be signed
    fdata = fopen(file_to_be_signed, "rb");
    if (fdata == NULL) {
        perror("Failed to open file to be signed");
        return 1;
    }

    // Compute the SHA-1 hash of the file
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fdata)) > 0) {
        SHA1_Update(&sha_ctx, buffer, bytes_read);
    }
    SHA1_Final(hash, &sha_ctx);

    fclose(fdata);

    // Open the private key file
    fprivate = fopen(private_key_file, "r");
    if (fprivate == NULL) {
        perror("Failed to open private key file");
        return 1;
    }

    // Read the private key
    rsa_private = PEM_read_RSAPrivateKey(fprivate, NULL, NULL, NULL);
    if (rsa_private == NULL) {
        fprintf(stderr, "Failed to read private key\n");
        fclose(fprivate);
        return 1;
    }

    // Determine the size of the RSA key in bytes
    int rsa_size = RSA_size(rsa_private);
    if (rsa_size <= 0) {
        fprintf(stderr, "Invalid RSA key size\n");
        RSA_free(rsa_private);
        fclose(fprivate);
        return 1;
    }

    // Allocate memory for the signature
    rsa_signature = (unsigned char*)malloc(rsa_size);
    if (rsa_signature == NULL) {
        perror("Failed to allocate memory for signature");
        RSA_free(rsa_private);
        fclose(fprivate);
        return 1;
    }

    // Generate the RSA signature
    unsigned int signature_length = 0;
    if (RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, rsa_signature, &signature_length, rsa_private) != 1) {
        fprintf(stderr, "Failed to generate RSA signature\n");
        free(rsa_signature);
        RSA_free(rsa_private);
        fclose(fprivate);
        return 1;
    }

    // Save the signature to a file
    fsign = fopen("signature.sig", "wb");
    if (fsign == NULL) {
        perror("Failed to open signature file");
        free(rsa_signature);
        RSA_free(rsa_private);
        fclose(fprivate);
        return 1;
    }

    fwrite(rsa_signature, signature_length, 1, fsign);
    printf("Signature successfully saved to signature.sig\n");

    // Clean up
    free(rsa_signature);
    RSA_free(rsa_private);
    fclose(fprivate);
    fclose(fsign);

    return 0;
}