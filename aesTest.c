#include <stdio.h>
#include "aes.h"

// /*  Encrypt Test   
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