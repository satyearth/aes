#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#define AES_BLOCK_SIZE 16  // AES block size in bytes

void aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(plaintext, ciphertext, &aes_key);
}

void aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *decryptedtext)
{
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_decrypt(ciphertext, decryptedtext, &aes_key);
}

int main()
{
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char plaintext[1024]; 
    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decryptedtext[AES_BLOCK_SIZE];

    printf("Enter plaintext (max 1023 characters): ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = 0;

    printf("Enter encryption key (exactly 16 characters): ");
    scanf("%16s", key);

    aes_encrypt(plaintext, strlen((char *)plaintext), key, ciphertext);

    aes_decrypt(ciphertext, AES_BLOCK_SIZE, key, decryptedtext);

    printf("\nPlaintext: %s\n", plaintext);

    printf("Ciphertext (hex): ");
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        printf("%02x", ciphertext[i]);
    printf("\n");

    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
