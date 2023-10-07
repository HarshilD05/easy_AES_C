#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif  

#include<stdint.h>

#define EXPORT __declspec(dllexport)

typedef enum {
	AES_128,
	AES_192,
	AES_256
}   AES_type;

/*  This is the standard Substitute Box used for the AES encryption and decryption. 
	The Inverse SBox will be automatically generated according to the sBox. 
*/
const uint8_t sBox[256] = {
	// 0   1     2     3     4     5     6     7     8     9     A     B     C     D     E     F 
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, // 0
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, // 1
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, // 2
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, // 3 
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, // 4
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, // 5
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, // 6
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, // 7
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, // 8
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, // 9
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, // A 
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, // B
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, // C
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, // D
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, // E
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16  // F
};

const uint8_t invSBox [256] = {
    //0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //a
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //b
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //c
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //d
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //e
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  //f
};

/** Gives the inverse Substitute Box for the substitute box provided.
 * @param sBox : pointer to the Substitute Box (Byte Array of size 256).
 * @return A pointer to the Inverse Substitute Box whihc was created. 
 *          Note that this memory allocation has to be handled by the user.
*/
EXPORT uint8_t* inverseSBoxGen (const uint8_t* sBox);

/** Utility Function to print the Substitute Box with the row and column indexing.
 * @param sBox : pointer to the Substitute Box (Byte Array of size 256).
*/
EXPORT void printSBox (const uint8_t* sBox);


/** Utility function used in testing to know values of the byte array  
 * @param byteArray : The pointer to the byte array to be printed
 * @param size : The total length of the byteArray
 * @param columns : The number of columns which should be printed in each line.
 *                  If value is given 0 then it will print the entire ByteArray in a single line.
 */
EXPORT void printBytesAsHex(const uint8_t* byteArray, size_t size, size_t columns);


/** Generates all the roundKeys required for the specific AES_type   
 * @param ogKey : The pointer to the byteArray which holds the original key
 * @param aesType : Defines original key size being used for AES (128, 192 or 256 bits).
 * 
 * @return : A pointer to the newly allocated memory which holds the expanded key.
 *          This memory allocated has to be handles by the user.
 */
EXPORT uint8_t* expandKey (uint8_t* ogKey, AES_type aesType);

/** Encrypts a 16-byte text block using the Advanced Encryption Standard (AES) algorithm.
 *
 * This function takes a 16-byte plaintext block and a 16-byte encryption key as input
 * and uses the specified AES encryption mode to securely transform the plaintext
 * into its encrypted form. The result is a 16-byte encrypted text block.
 *
 * @param text Pointer to a 16-byte plaintext block to be encrypted.
 * @param key Pointer to a 16-byte encryption key used for the encryption process.
 * @param aesType The type of AES encryption mode to use (128, 192, or 256 bits).
 * @return Pointer to a 16-byte array containing the encrypted text block.
 *         The caller is responsible for managing the memory of the returned array.
 *
 * @note The `text` and `key` pointers must point to valid memory locations with at least 16 bytes of data.
 * @note The returned encrypted text block should be considered sensitive data and handled accordingly.
 * @note The caller is responsible for managing the memory of the returned encrypted text block.
 * @note The AES key size is determined by the `aesType` parameter: 128, 192, or 256 bits.
 *
 * @see For more information about the AES algorithm and its encryption modes, refer to the AES specification.
 */
EXPORT uint8_t* AES_cipher (uint8_t* text, uint8_t* key, AES_type aesType);

/** Decrypts a 16-byte encrypted text block using the Advanced Encryption Standard (AES) algorithm.
 *
 * This function takes a 16-byte encrypted text block and a decryption key as input
 * and uses the specified AES decryption mode to securely transform the encrypted text
 * back into its original plaintext form. The result is a 16-byte decrypted text block.
 *
 * @param encryptedText Pointer to a 16-byte encrypted text block to be decrypted.
 * @param key Pointer to a 16-byte decryption key used for the decryption process.
 * @param aesType The type of AES decryption mode to use (128, 192, or 256 bits).
 * @return Pointer to a 16-byte array containing the decrypted text block.
 *         The caller is responsible for managing the memory of the returned array.
 *
 * @note The `encryptedText` and `key` pointers must point to valid memory locations with at least 16 bytes of data.
 * @note The returned decrypted text block should be handled as sensitive data and stored securely.
 * @note The caller is responsible for managing the memory of the returned decrypted text block.
 * @note The AES key size is determined by the `aesType` parameter: 128, 192, or 256 bits.
 * @note This function performs basic Electronic Codebook (ECB) decryption. No Initialization Vector (IV) is used.
 *
 * @see For more information about the AES algorithm and its decryption modes, refer to the AES specification.
 */
EXPORT uint8_t* AES_invCipher (uint8_t* encryptedText, uint8_t* key, AES_type aesType);


/** Adds padding to the input text according to the PKCS standards ONLY when the text length is not a multiple of the blockSize.
 * @param text : the pointer to the plain Text
 * @param blockSize : the size of 1 block in Bytes.
 * 
 * @return : Returns a pointer to the padded Text whose length is a multiple of the blockSize.
 *          This memory allocation has to be handled by the user.
 * @see PKCS padding : https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method
 */
EXPORT char* addPadding (char* text, size_t blockSize);

/** Removes the padding from a padded Text returned from the addPadding() function.
 * @param paddedText : The pointer to the paddedText
 * @param blockSize : The size of 1 block.
 */
EXPORT void removePadding (char* paddedText, size_t blockSize);

/** Converts a Byte Array to a Hexadecimal String.
 * This Helps in correctly transferring the actual Byte Array without misinterpretation due to non-printable ASCII characters.
 *  
 * @param byteArray : the pointer to the Byte Array to be converted.
 * @param length : the length of the Byte Array
 * 
 * @return Returns a pointer to the HexaDecimal string.
 *          This memory allocation has to be handled by the user.
 */
EXPORT char* bytesToHexString (uint8_t* byteArray, size_t length);

/** Converts a HexaDecimal string to a byte array.
 * @note The Hexadecimal String should have no spaces in it and must be null terminated.
 * 
 * @param hexString : Thepointer to the HexaDecimal String
 */
EXPORT uint8_t* hexStringToByteArray(const char* hexString);


/** Encrypts plaintext using the Advanced Encryption Standard (AES) algorithm.
 *
 * This function provides an easy-to-use interface for AES encryption. It takes a plaintext
 * of any length and performs PKCS padding to make its size a multiple of 16 bytes (e.g., 16, 32, 48, ...).
 * The function then performs AES encryption on each 16-byte block of the padded plaintext.
 * If an Initialization Vector (IV) is provided, AES Cipher-Block Chaining (CBC) encryption is used.
 * If IV is NULL, regular Electronic Codebook (ECB) encryption is performed.
 *
 * @param plainText The plaintext to be encrypted. The length is not restricted to multiples of 16 bytes.
 * @param keyHexStr The AES encryption key provided as a hexadecimal string. Will be converted to a byte array internally.
 * @param IVHexStr The Initialization Vector (IV) provided as a hexadecimal string, or NULL for ECB mode.
 *                Will be converted to a byte array internally.
 * @param aesType The type of AES encryption mode to use (128, 192, or 256 bits).
 * @return A dynamically allocated char array containing the encrypted data as a hexadecimal string.
 *         The caller is responsible for managing the memory of the returned array.
 *
 * @note The `keyHexStr` and `IVHexStr` parameters must be valid hexadecimal strings.
 * @note The returned encrypted data is a hexadecimal string representing the value of the encrypted byte array.
 * @note The caller is responsible for managing the memory of the returned encrypted data array.
 * @note The AES key size is determined by the `aesType` parameter: 128, 192, or 256 bits.
 * @note If an IV is provided, AES CBC encryption is used. If IV is NULL, AES ECB encryption is performed.
 * @note The function internally handles PKCS padding for plaintext blocks that are not a multiple of 16 bytes.
 *
 * @see For more information about the AES algorithm and its encryption modes, refer to the AES specification.
 * @see PKCS#7 padding: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method
 */
EXPORT char* AES_encrypt (char* plainText, char* keyHexStr, char* IVHexStr, AES_type aesType);

/** Decrypts data encrypted using the Advanced Encryption Standard (AES) algorithm.
 *
 * This function provides an easy-to-use interface for decrypting data that was encrypted
 * using the AES_encrypt function. It takes the encrypted data as a hexadecimal string,
 * the AES decryption key as a hexadecimal string, and the Initialization Vector (IV)
 * as a hexadecimal string (or NULL for ECB mode). The function then performs AES decryption
 * on each 16-byte block of the encrypted data and removes any padding added during encryption.
 *
 * @param encryptedHexStr The encrypted data as a hexadecimal string.
 * @param keyHexStr The AES decryption key provided as a hexadecimal string. Will be converted to a byte array internally.
 * @param IVHexStr The Initialization Vector (IV) provided as a hexadecimal string, or NULL for ECB mode.
 *                Will be converted to a byte array internally.
 * @param aesType The type of AES encryption mode used (128, 192, or 256 bits).
 * @return A dynamically allocated char array containing the original plaintext data.
 *         The caller is responsible for managing the memory of the returned array.
 *
 * @note The `encryptedHexStr`, `keyHexStr`, and `IVHexStr` parameters must be valid hexadecimal strings.
 * @note The returned plaintext data is the original content before encryption and any padding added.
 * @note The caller is responsible for managing the memory of the returned plaintext data array.
 * @note The AES key size is determined by the `aesType` parameter: 128, 192, or 256 bits.
 * @note If an IV is provided, AES CBC decryption is used. If IV is NULL, AES ECB decryption is performed.
 * @note The input `encryptedHexStr` should be the result of the AES_encrypt function.
 *
 * @see AES_encrypt function documentation for more information about AES encryption and usage.
 * @see For more information about the AES algorithm and its decryption modes, refer to the AES specification.
 */
EXPORT char* AES_decrypt (char* encryptedHexString, char* keyHexStr, char* IVHexStr, AES_type aesType);

#ifdef __cplusplus
}
#endif  // cplussplus }

#endif  // AES_H