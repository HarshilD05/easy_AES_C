#include <stdio.h>
#include "aes.h"

// /*  AES_Encrypt Test   
int main () {  
    char* key = "4C336B52396E5970586A54715A7756734366556749684F644561426D417A506200";
    char* text = "Hello World, This is AES Encryption!";
    char *iv = "5f12ab9f2cd7e48f736e0a5b98f1c27d00";
    AES_type aesType = AES_256;

    printf("\nOg text : \n%s\n", text);

    char* encryptedHexStr = AES_encrypt(text, key, iv, aesType);
    printf("\nEncrypted Hex String : \n%s\n", encryptedHexStr);

    char* decryptedText = AES_decrypt(encryptedHexStr, key, iv, aesType);
    printf("\nDecrypted Text : \n%s\n", decryptedText);

    printf("\n");
    return 0;
}
// */

/*  AES_Cipher Test
int main () {
    uint8_t text[16+1] = {0x5f, 0x12, 0xab, 0x9f, 0x2c, 0xd7, 0xe4, 0x8f, 0x73, 0x6e, 0x0a, 0x5b, 0x98, 0xf1, 0xc2, 0x7d, 0x00 };
    uint8_t key[32+1] = {0x4C, 0x33, 0x6B, 0x52, 0x39, 0x6E, 0x59, 0x70, 0x58, 0x6A, 0x54, 0x71, 0x5A, 0x77, 0x56, 0x73,
                        0x43, 0x66, 0x55, 0x67, 0x49, 0x68, 0x4F, 0x64, 0x45, 0x61, 0x42, 0x6D, 0x41, 0x7A, 0x50, 0x62, 0x00};

    printf("\nOg Text : ");
    printBytesAsHex(text, 16, 0);

    uint8_t* encryptedText = AES_cipher(text, key, AES_256);
    printf("\nEncrypted Text : ");
    printBytesAsHex(encryptedText, 16, 0);

    uint8_t* decryptedText = AES_invCipher(encryptedText, key, AES_256);
    printf("\nDecrypted Text : ");
    printBytesAsHex(decryptedText, 16, 0);

    printf("\n");
    return 0;
}
// */