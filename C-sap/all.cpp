//------------------------------------------------------------------------   HASH   --------------------------------------------------------------------------------------------------
/*
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define MESSAGE_CHUNK 200

void compute_sha1_hash(const char* filename, unsigned char* finalDigest) {
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

int main() {
    const char* filename = "D:\\C\\Refactored_Hash\\demo.txt";
    unsigned char finalDigest[SHA_DIGEST_LENGTH];
    compute_sha1_hash(filename, finalDigest);

    printf("\nSHA1 = ");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02X ", finalDigest[i]);
    }
    printf("\n");

    return 0;
}

//#include <stdio.h>
//#include <malloc.h>
//#include <openssl/md5.h>
//#include <openssl/sha.h>
//#pragma warning(disable: 4996)
//
//#define MESSAGE_CHUNK 200
//
//int main(int argc, char** argv)
//{
//	const char* filename = "D:\\C\\Refactored_Hash\\demo.txt";
//
//	//if (argc != 2) {
//	//	printf("\n Usage Mode: ProgMainMD5.exe fSrc.txt \n\n");
//	//	return 1;
//	//}
//
//
//	FILE* f = NULL;
//	errno_t err;
//	SHA_CTX ctx;
//
//	unsigned char finalDigest[SHA_DIGEST_LENGTH];
//	SHA1_Init(&ctx); // initialization of the MD5_CTX structure
//
//	unsigned char* fileBuffer = NULL;
//
//	err = fopen_s(&f, filename, "rb");
//	//err = fopen_s(&f, argv[1], "rb");
//
//	if (err != 0) {
//		printf("Error opening the file\n");
//		return 1;
//	}
//
//	unsigned char* tmpBuffer_Chunk = (unsigned char*)malloc(MESSAGE_CHUNK);
//
//	size_t read_length = MESSAGE_CHUNK;
//	while (read_length == MESSAGE_CHUNK) {
//		read_length = fread(tmpBuffer_Chunk, 1, MESSAGE_CHUNK, f);
//		SHA1_Update(&ctx, tmpBuffer_Chunk, read_length);
//	}
//
//	SHA1_Final(finalDigest, &ctx); // saves the A, B, C, D blocks in the right order into the message digest buffer
//
//	int count = 0;
//	printf("\nMD5 = ");
//	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
//		printf("%02X ", finalDigest[i]);
//		printf(" ");
//	}
//
//	printf("\n");
//
//	fclose(f);
//
//	return 0;
//}



//int main() {
//	unsigned char input[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//							  0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//							  0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
//							  0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
//
//	int remaining = sizeof(input) / sizeof(char);
//	int offset = 0;
//	int read = INPUT_BLOCK;
//	unsigned char digest[SHA_DIGEST_LENGTH];
//	SHA_CTX ctx;
//	SHA1_Init(&ctx);
//
//	while (remaining > 0) {
//		if (remaining < INPUT_BLOCK) {
//			read = remaining;
//		}
//		SHA1_Update(&ctx, (input + offset), read);
//		remaining = remaining - read;
//		offset = offset + read;
//	}
//
//
//	SHA1_Final(digest, &ctx);
//
//	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
//		printf("%02X ", digest[i]);
//	}
//	return 0;
//}

/*
#define INPUT_BLOCK 64 // Define the block size for processing

unsigned char* computeSHA1(const unsigned char* input, size_t input_size) {
    int remaining = input_size;
    int offset = 0;
    int read = INPUT_BLOCK;
    unsigned char* digest = malloc(SHA_DIGEST_LENGTH);
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

*/




//Use this when reading file containing hex data in text format (0102030405060708090a0b0c0d0e0f1102034455060708090a0b0c0d0e0f2)
//#include <stdio.h>
//#include <stdlib.h>
//#include <openssl/sha.h>
//
//#define INPUT_BLOCK_LENGTH 15
//
//#pragma warning(disable: 4996)
//
//// TODO: add implementation for SHA-256
//
//int main()
//{
//	unsigned char input[INPUT_BLOCK_LENGTH];
//	FILE* f = NULL;
//	SHA_CTX context;
//
//	f = fopen("input-SHA1-txtfile.txt", "rb");
//	fseek(f, 0, SEEK_END);
//	unsigned int remaining_length = ftell(f); // initial value: total length of the file
//	fseek(f, 0, SEEK_SET);
//
//	SHA1_Init(&context);
//
//	while (remaining_length > 0)
//	{
//		unsigned char hex_pair[2];
//		unsigned char i = 0;
//		if (remaining_length > (INPUT_BLOCK_LENGTH * 2)) // double length because eah hex-pair means 2 bytes in text/ASCII representation
//		{
//			for (i = 0; i < INPUT_BLOCK_LENGTH; i++)
//			{
//				fread(hex_pair, sizeof(unsigned char), sizeof(hex_pair) / sizeof(unsigned char), f); // read 2 bytes from the text file corresponding to one single hex pair
//				input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
//			}
//
//			// sha1 update done for 15-byte input 
//			SHA1_Update(&context, input, INPUT_BLOCK_LENGTH); // one data block having exactly 15 bytes is processed			
//			remaining_length -= (INPUT_BLOCK_LENGTH * 2); // update the remaining length (double for text representation read from the file) of the entire input to be processed later
//		}
//		else
//		{
//			unsigned char remaining_hex_pairs = remaining_length / 2;
//			for (i = 0; i < remaining_hex_pairs; i++) // 2 because the hex pair has as text has a double no of bytes
//			{
//				fread(hex_pair, sizeof(unsigned char), sizeof(hex_pair) / sizeof(unsigned char), f); // read 2 bytes from the text file corresponding to one single hex pair
//				input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
//			}
//
//			// sha1 update done for less or equal to 15 bytes as data length
//			SHA1_Update(&context, input, remaining_hex_pairs); // remained data block is processsed
//			remaining_length -= remaining_length; // remaining_length is zero; there is no more data to be processed by SHA1_Update rounds
//		}
//	}
//
//	unsigned char output[SHA_DIGEST_LENGTH];
//	SHA1_Final(output, &context);
//
//	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
//	{
//		printf(" %02X", output[i]);
//	}
//	printf("\n\n");
//
//	return 0;
//}

/*

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

*/

/*

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

#include <stdio.h>
#include <stdlib.h>

/**
 * Writes an unsigned char buffer to a file as ASCII.
 *
 * @param buffer     Pointer to the buffer to write.
 * @param size       Size of the buffer in bytes.
 * @param file_path  Path to the file where the buffer will be written.
 * @return           0 on success, -1 on failure.

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




*/

//-----------------------------------------------------------------------  AES  -------------------------------------------------------------------------------



/*

/**
 * Decrypts a file using AES-ECB mode.
 *
 * @param file_path Path to the file to decrypt.
 * @param key_128   The 128-bit AES key for decryption.
 * @param output_size Pointer to store the size of the decrypted data.
 * @return Pointer to the decrypted data (dynamically allocated). Caller must free it.
 *         Returns NULL on failure.
 
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

*/

/*


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

*/