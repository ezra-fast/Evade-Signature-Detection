# Evading AV in C

Evade.c successfully applies AES-256 CBC decryption to an encrypted meterpreter payload at runtime, injecting it into allocated memory for a successful shell. The current version relies on the cURL libary for header files and the OpenSSL library for cryptographic operations. The encrypted payload is obtained by running encryptDecrypt.c with a normal meterpreter payload, grabbing the formatted ciphertext (and the ciphertext length), ensuring that the payload will actually give a shell in the meantime. That ciphertext and its length are then hardcoded into evade.c and compiled as needed. This process will be cleaner in the future.

Compilation: 
```shell [Command line]
gcc .\real.c C:\Users\super\source\repos\openssl\ms\applink.c -o .\real -IC:\curl\include\ -L"C:\Program Files\OpenSSL-Win64" -l:libcrypto-3-x64.dll -l:libssl-3-x64.dll
```

