#include"aes.h"
#include<stdio.h>
#include<stdbool.h>
#include<stdlib.h>	// For malloc() and rand()
#include<string.h>	// for memcpy()

/*  Functions required for handling GF(2^8) polynomial arithmetic   */
uint8_t reduceGF2_8 (unsigned poly, unsigned irreducablePoly) { 
    uint8_t msbPoly = 0;
    uint8_t msbIrrPoly = 0;
    uint8_t diff = 0;
    unsigned p;

    // Calculating the MSB Pos of Irreducable polynomial
    p = irreducablePoly;
    while (p) {
        ++msbIrrPoly;
        p >>= 1;
    }

    // Reducing the Polynomial with the irreducable polynomial
    while (poly > 0xFF) {
        // Calculating the MSB Pos of polynomial
        p = poly;
        msbPoly = 0;
        while (p) {
            ++msbPoly;
            p >>= 1;
        }

        diff = msbPoly - msbIrrPoly;

        poly ^= irreducablePoly<<diff;
    }

    return (poly & 0xFF);
}

uint8_t additionGF2_8 (uint8_t a, uint8_t b) {
    return a^b;
}

uint8_t multiplyGF2_8 (uint8_t a, uint8_t b) {
    unsigned temp;
    uint8_t ans = 0;
    uint8_t pow = 0;

    while (a) {
        if (a & 0x01) {
            temp = b << pow;

            if (temp > 0xFF) temp = reduceGF2_8(temp,0x11B);

            ans = additionGF2_8(ans, temp);
        }
        a>>=1;
        ++pow;
    }

    return ans;
}

void print_GF2_polynomial(uint8_t num) {
    bool isFirstTerm = true;

    for (int i = 7; i >= 0; --i) {
        if ((num >> i) & 0x01) {
            if (!isFirstTerm) {
                printf(" + ");
            }

            if (i == 0) {
                printf("1");
            } else {
                printf("x^%d", i);
            }

            isFirstTerm = false;
        }
    }

    if (isFirstTerm) {
        // If no terms are present, print "0" polynomial
        printf("0");
    }
    
    printf("\n");
}


/*  Functions required to handle SBox generation    */

/*  Generates a random byte (number between 0x00 and 0xFF)  */
uint8_t rngByte() {
    return (rand()%0x100);
}

uint8_t* sBoxGen (unsigned int seed) {  
	size_t itt = 0xFF;
	// Seting the Seed value for RNG
	srand(seed);
	// Allocating Memory for the sBox
	uint8_t* sBox = (uint8_t*) calloc(0x100,sizeof(uint8_t) );

	uint8_t value;
	uint8_t start = rngByte();
	uint8_t coordinate = 0x00;

	while (itt) {
		// When the last empty box is left to fill put the starting coordinates
		if (itt == 1) {
			sBox[coordinate] = start;
			--itt;
		}
		
		value = rngByte();
		
		// Checking if value is repeated
		if ( (value != start) && (sBox[value] == 0) && (value != coordinate) ) {
			sBox[coordinate] = value;
			coordinate = value;
			--itt;
		}
	}

	return sBox;

};

/** Gives the inverse Substitute Box for the substitute box provided.
 * @param sBox : pointer to the Substitute Box (Byte Array of size 256).
 * @return A pointer to the Inverse Substitute Box whihc was created. 
 *          Note that this memory allocation has to be handled by the user.
*/
EXPORT uint8_t* inverseSBoxGen (const uint8_t* sBox) {
    const size_t rows = 16;
    const size_t columns = 16;
    size_t i;

    uint8_t* inverseSBox = (uint8_t*)calloc(rows*columns,sizeof(uint8_t) );

    for (i = 0;i<=0xFF;++i) {
        inverseSBox[ sBox[i] ] = i;
    }

    return inverseSBox;
}

/** Utility Function to print the Substitute Box with the row and column indexing.
 * @param sBox : pointer to the Substitute Box (Byte Array of size 256).
*/
EXPORT void printSBox (const uint8_t* sBox) {
    const size_t rows = 16;
    const size_t columns = 16;

    // Printing Column Index
    printf("\n/0 ");
    for (int i = 1;i<16;++i) {
        printf(" %x ",i);
    }
    printf("\n");

    // Printing the SBox
    for (int i = 0;i<rows;++i) {
        printf("\n");
        for (int j = 0;j<columns;++j) {
            printf("%02x ", sBox[i*columns + j] );
        }
        
        // Printing Row Index
        printf("\t//%x",i);

    }

    printf("\n");
}


/** Utility function used in testing to know values of the byte array  
 * @param byteArray : The pointer to the byte array to be printed
 * @param size : The total length of the byteArray
 * @param columns : The number of columns which should be printed in each line.
 *                  If value is given 0 then it will print the entire ByteArray in a single line.
 */
EXPORT void printBytesAsHex(const uint8_t* byteArray, size_t size, size_t columns) {
    if (columns == 0) columns = size;
    for (size_t i = 0; i < size; i++) {
		if (i % columns == 0) printf("\n");
        printf("%02X ", byteArray[i]);
    }
    printf("\n");
}

/** Generates all the roundKeys required for the specific AES_type   
 * @param ogKey : The pointer to the byteArray which holds the original key
 * @param aesType : Defines original key size being used for AES (128, 192 or 256 bits).
 * 
 * @return : A pointer to the newly allocated memory which holds the expanded key.
 *          This memory allocated has to be handles by the user.
 */
EXPORT uint8_t* expandKey (uint8_t* ogKey, AES_type aesType) {
    int Nr;
    int Nk;
    uint8_t Rcon[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

    switch (aesType) {
        case AES_128 : 
        Nk = 4;
        Nr = 10;
        break;

        case AES_192 : 
        Nk = 6;
        Nr = 12;
        break;

        case AES_256 : 
        Nk = 8;
        Nr = 14;
        break;

        default : 
        printf("\nERROR : Please Enter AES_Type...\n");
        return NULL;
    }

    // Allocating Memory for the expanded Key
    uint8_t* expandedKey = (uint8_t*) calloc( 16*(Nr+1) , sizeof(uint8_t) );
    uint8_t tempWord[4];

    // Copying the Original Key to the start of Expanded Key
    for (int i = 0;i<Nk;++i) {
        for (int j = 0;j<4;++j) {
            expandedKey[4*i+j] = ogKey[4*i+j];
        }
        
    }

    // Adding the remaining Round Keys
    for (int i = Nk*4;i<16*(Nr+1);i+=4) {
        // Copying the previous word into tempWord
        for (int j = 0;j<4;++j) {
            tempWord[j] = expandedKey[i-4+j];
        }

        // G Function called for every Nk Byte
        if ( (i/4)%Nk == 0) {
            // Rotating Left
            uint8_t temp = tempWord[0];
            tempWord[0] = tempWord[1];
            tempWord[1] = tempWord[2];
            tempWord[2] = tempWord[3];
            tempWord[3] = temp;

            // Substitute Box
            for (int j = 0;j<4;++j) {
                tempWord[j] = sBox[ tempWord[j] ];
            }

            // Rcon
            tempWord[0] ^= Rcon[ (i/4)/Nk ];

        }

        // For AES_256 for every (Nk+4)th word do Substitute Box
        if (aesType == AES_256 && (i/4)%Nk == 4 ) {
            for (int j = 0;j<4;++j) {
                tempWord[j] = sBox[ tempWord[j] ];
            }

        }

        // Xoring with the word Nk Places Prior
        for (int j = 0;j<4;++j) {
            expandedKey[i+j] = tempWord[j] ^ expandedKey[i-(4*Nk)+j];
        }

    }

    return expandedKey;
}

/**  Switches the 4x4 (16 Byte) state matrix between Row Major and Column Major for AES operations.
 * @param state : A pointer to the 16 byte array which holds the state matrix
 */
void switchStateBetweenRowOrColumnMajor (uint8_t* state) {
    uint8_t colState[16];

    // Creating the new column Major Matrix
    for (int i = 0;i<4;++i) {
        for (int j =0;j<4;++j) {
            colState[4*j+i] = state[4*i+j];
        }

    }

    // Copying the new column major matrix on the current state
    for (int i = 0;i<16;++i) {
        state[i] = colState[i];
    }

}


/*  Functions used for AES encryption   */
/** XORS the 16 byte Key with the 16 byte State Matrix.
 * @note This function needs the state to be in a Column Major State and the Key has to be in a Row Major State.
 * 
 * @param state : The pointer to the 16 byte state matrix.
 * @param key : The pointer to the 16 byte RoundKey to be added 
 */
void addKey (uint8_t* state, uint8_t* key) {
    for (int i = 0;i<4;++i) {
        for (int j = 0;j<4;++j) {
            state[4*j+i] ^= key[4*i+j];
        }

    }

}

/** Performs Left Rotation on rows of the State Matrix.
 * Rotates Row 0 : 0 times, Row 1 : Once, Row 2 : Twice, Row 3 : Thrice.
 * @note The State provided in this function should be a Column Major State Matrix, not just the plain text
 * 
 * @param state : the poointer to the 16 byte state matrix
 */
void rotateRows (uint8_t* state) {    
    // Rotating Row 0 : none, Row 1 : Rotate Left, Row 2 : Rotate Left Twice, Row 3 : Rotate Left Thrice
    for (int i = 0;i<4;++i) {   // Number of Rotates
        for (int j = 1;j<=i;++j) {  // Actually Performing the Rotates
            uint8_t temp = state[i*4];
            state[i*4] = state[i*4+1];
            state[i*4+1] = state[i*4+2];
            state[i*4+2] = state[i*4+3];
            state[i*4+3] = temp;
        }
        
    }

}

/** Performs the Mix Columns operation of the AES.
 * @param state : the pointer to the 16 byte State Matrix.
 * @note the State Matrix should be in Column Major form, not the Row Major Plain Text
 */
void mixColumns (uint8_t* state) {
    uint8_t matrix[16] = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02
    };

    uint8_t temp[4];

    for (int i = 0;i<4;++i) {
        // Getting Each element of the New column by matrix multiplication
        for (int j = 0;j<4;++j) {
            temp[j] = multiplyGF2_8(state[i], matrix[4*j] ) ^ multiplyGF2_8(state[4+i] , matrix[4*j+1] ) ^ multiplyGF2_8( state[8+i] , matrix[4*j+2] ) ^ multiplyGF2_8( state[12+i], matrix[4*j+3] );
        }

        // Copying the contents of the new column to our state
        for (int j = 0;j<4;++j) {
            state[4*j+i] = temp[j];
        }

    }

}

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
EXPORT uint8_t* AES_cipher (uint8_t* text, uint8_t* key, AES_type aesType) {
    int Nk;
    int Nr;

    switch (aesType) {
        case AES_128 : 
        Nk = 4;
        Nr = 10;
        break;

        case AES_192 : 
        Nk = 6;
        Nr = 12;
        break;

        case AES_256 : 
        Nk = 8;
        Nr = 14;
        break;

        default : 
        printf("\nERROR : Please Enter AES_Type...\n");
        return NULL;
    }

    uint8_t* expandedKey = expandKey(key, aesType);
    uint8_t* encryptedText = (uint8_t*)calloc(16+1,sizeof(uint8_t));    // Ensuring NULL termination of the encrypted Text (16+1)


    // Copying the Text to EncryptedText Buffer
    for (int i = 0;i<16;++i) {
        encryptedText[i] = text[i];
    }

    // Converting to Column Major to make the state matrix used for AES operations
    switchStateBetweenRowOrColumnMajor(encryptedText);

    /* Initial Round */
    // Adding Key
    addKey(encryptedText,expandedKey);

    /* Main Rounds  */
    for (int i = 1;i<Nr;++i) {
        // Substitute Bytes
        for (int j = 0;j<16;++j) {
            encryptedText[j] = sBox[ encryptedText[j] ];
        }
        
        // Rotating Rows
        rotateRows(encryptedText);

        // Mixing Columns
        mixColumns(encryptedText);

        // Adding Key
        addKey(encryptedText, expandedKey+16*i);

    }

    /* Final Round  */
    // Substitute Bytes
    for (int j = 0;j<16;++j) {
        encryptedText[j] = sBox[ encryptedText[j] ];
    }

    // Rotating Rows
    rotateRows(encryptedText);

    // Adding Key
    addKey(encryptedText, expandedKey+16*Nr);

    switchStateBetweenRowOrColumnMajor(encryptedText); // Making the encrypted Text Row Major for readability

    /*  Cleanup */
    free(expandedKey);

    return encryptedText;

}


/*  Functions used for AES decryption   */
/** Performs the inverse of the rotateRows() function. It performs Right Rotation.
 * Rotates Row 0 : 0 times, Row 1 : Once, Row 2 : Twice, Row 3 : Thrice.
 * 
 * @param state : the pointer to the 16 byte state matrix.
 * @note The State Matrix should be in Column Major State.
 */
void invRotateRows (uint8_t* state) {
    // Rotating Row 0 : none, Row 1 : Rotate Right, Row 2 : Rotate Right Twice, Row 3 : Rotate Right Thrice
    for (int i = 0;i<4;++i) {
        for (int j = 1;j<=i;++j) {
            uint8_t temp = state[i*4+3];
            state[i*4+3] = state[i*4+2];
            state[i*4+2] = state[i*4+1];
            state[i*4+1] = state[i*4];
            state[i*4] = temp;
        }

    }

}

/** Performs the inverse of the mixColumns() function
 * @param state : The pointer to the 16 byte State Matrix.
 * @note The State matrix should be in Column Major Form
 */
void invMixColumns (uint8_t* state) {
    uint8_t matrix[16] = {
        0x0E, 0x0B, 0x0D, 0x09,
        0x09, 0x0E, 0x0B, 0x0D,
        0x0D, 0x09, 0x0E, 0x0B,
        0x0B, 0x0D, 0x09, 0x0E
    };

    uint8_t temp[4];

    for (int i = 0;i<4;++i) {
        // Getting Each element of the New column by matrix multiplication
        for (int j = 0;j<4;++j) {
            temp[j] = multiplyGF2_8(state[i], matrix[4*j] ) ^ multiplyGF2_8(state[4+i] , matrix[4*j+1] ) ^ multiplyGF2_8( state[8+i] , matrix[4*j+2] ) ^ multiplyGF2_8( state[12+i],matrix[4*j+3] );
        }

        // Copying the contents of the new column to our state
        for (int j = 0;j<4;++j) {
            state[4*j+i] = temp[j];
        }

    }

}

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
EXPORT uint8_t* AES_invCipher (uint8_t* encryptedText, uint8_t* key, AES_type aesType) {
    int Nk;
    int Nr;

    switch (aesType) {
        case AES_128 : 
        Nk = 4;
        Nr = 10;
        break;

        case AES_192 : 
        Nk = 6;
        Nr = 12;
        break;

        case AES_256 : 
        Nk = 8;
        Nr = 14;
        break;

        default : 
        printf("\nERROR : Please Enter AES_Type...\n");
        return NULL;
    }

    uint8_t* expandedKey = expandKey(key, aesType);
    uint8_t* invSBox = inverseSBoxGen( (const uint8_t*)&sBox);
    uint8_t* decryptedText = (uint8_t*)calloc(16+1,sizeof(uint8_t));    // Ensuring NULL termination of the decrypted Text (16+1)

    // Copying encryptedText to decryptedText buffer
    for (int i = 0;i<16;++i) {
        decryptedText[i] = encryptedText[i];
    }

    // Converting to column Major to form state Matrix used for AES operations
    switchStateBetweenRowOrColumnMajor(decryptedText);

    /* Initial Round    */
    // XORing with Key
    addKey(decryptedText, expandedKey+16*Nr);
    
    // inverse Rotate Rows (Rotate Right)
    invRotateRows(decryptedText);

    // inverse Substitute Box
    for (int i = 0;i<16;++i) {
        decryptedText[i] = invSBox[ decryptedText[i] ];
    }

    /* Main Rounds  */
    for (int i = 16*(Nr-1);i>0;i-=16) {
        // XOR with Key
        addKey(decryptedText, expandedKey+i);
        
        // Inverse Mix Columns
        invMixColumns(decryptedText);
        
        // Inverse Rotate Rows (Rotate Right)
        invRotateRows(decryptedText);

        // Inverse Substitute Box
        for (int j = 0;j<16;++j) {
            decryptedText[j] = invSBox[ decryptedText[j] ];
        }

    }


    /* Final Round */
    // XOR with Key
    addKey(decryptedText, expandedKey);

    switchStateBetweenRowOrColumnMajor(decryptedText);    // Making decrypted Text Row Major

    /*  Cleanup */
    free(expandedKey);
    free(invSBox);

    return decryptedText;
}

/*  Functions used in the FINAL AES_encrypt() and AES_decrypt() functions   */

/** Adds padding to the input text according to the PKCS standards ONLY when the text length is not a multiple of the blockSize.
 * @param text : the pointer to the plain Text
 * @param blockSize : the size of 1 block in Bytes.
 * 
 * @return : Returns a pointer to the padded Text whose length is a multiple of the blockSize.
 *          This memory allocation has to be handled by the user.
 * @see PKCS padding : https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method
 */
EXPORT char* addPadding (char* text, size_t blockSize) {
    size_t len = strlen(text);  
    size_t diff = blockSize - (len%blockSize);
    
    // Allocating memory for the new padded Text
    char* paddedText = (char*) calloc(len+diff+1, sizeof(char) );
    // Copying contents of the previous text to the padded Text
    memcpy(paddedText, text, len);

    // adding padding
    for (int i = 0;i<diff;++i) {
        paddedText[len+i] = diff;
    }

    paddedText[len+diff] = '\0';  // NULL terminate the string

    return paddedText;
}

/** Removes the padding from a padded Text returned from the addPadding() function.
 * @param paddedText : The pointer to the paddedText
 * @param blockSize : The size of 1 block.
 */
EXPORT void removePadding (char* paddedText, size_t blockSize) {
    size_t len = strlen(paddedText);
    size_t padding = paddedText[len-1];

    if (padding < blockSize) {
        for (int i = 0;i<=padding;++i) {
            paddedText[len-i] = '\0';   // Clearing all bytes of padding
        }

    }
    
}

/** Converts a Byte Array to a Hexadecimal String.
 * This Helps in correctly transferring the actual Byte Array without misinterpretation due to non-printable ASCII characters.
 *  
 * @param byteArray : the pointer to the Byte Array to be converted.
 * @param length : the length of the Byte Array
 * 
 * @return Returns a pointer to the HexaDecimal string.
 *          This memory allocation has to be handled by the user.
 */
EXPORT char* bytesToHexString (uint8_t* byteArray, size_t length) {
    char* hexString = (char*)malloc(length * 2 + 1); // Two characters per byte plus null terminator
    if (hexString == NULL) {
        return NULL; // Memory allocation failed
    }

    for (size_t i = 0; i < length; ++i) {
        snprintf(hexString + i * 2, 3, "%02X", byteArray[i]);
    }

    hexString[length * 2] = '\0'; // Null-terminate the hex string
    return hexString;
} 

/** Converts a HexaDecimal string to a byte array.
 * @note The Hexadecimal String should have no spaces in it and must be null terminated.
 * 
 * @param hexString : Thepointer to the HexaDecimal String
 */
EXPORT uint8_t* hexStringToByteArray(const char* hexString) {
    // Return NULL if no pointer is passed
    if (hexString == NULL) return NULL;

    size_t hexLen = strlen(hexString);
    if (hexLen % 2 != 0) {
        return NULL; // Hex string length must be even
    }

    size_t byteLen = hexLen / 2;
    uint8_t* byteArray = (uint8_t*)malloc(byteLen+1);
    if (byteArray == NULL) {
        return NULL; // Memory allocation failed
    }

    for (size_t i = 0; i < byteLen; ++i) {
        sscanf(hexString + i * 2, "%2hhX", &byteArray[i]);
    }

    byteArray[byteLen] = 0x00;  // NULL terminating the Byte ARRAY

    return byteArray;
}


/*  Main easy-to-use AES functions  */
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
EXPORT char* AES_encrypt (char* plainText, char* keyHexStr, char* IVHexStr, AES_type aesType) {
    // Adding Padding to the plain Text
    char* paddedText = addPadding(plainText, 16);
    size_t textLength = strlen(paddedText);

    // Converting input Key to Byte ARRAY
    uint8_t* key = hexStringToByteArray(keyHexStr);
    // Converting input IV to BYTE ARRAY
    uint8_t* iv = hexStringToByteArray(IVHexStr);

    
    // Creating Memory for encrypted Text
    uint8_t* encryptedText = (uint8_t*) calloc(textLength, sizeof(uint8_t) );

    // XORing the IV with the first Text Block if IV is provided for CBC mode
    if (iv != NULL) {
        switchStateBetweenRowOrColumnMajor(iv);   // Converting the IV to Column Major 
        addKey(paddedText, iv);
    }

    /*  Main Encryption */
    // First Text Block
    uint8_t* encryptedState = AES_cipher(paddedText, key, aesType);
    // Copying the Encrypted State to the Final Encrypted Text
    memcpy(encryptedText, encryptedState, 16);

    // Remianing Text Blocks
    for (int i = 16;i<textLength;i+=16) {
        // If CBC mode then XOR previous encrypted State to the next
        if (iv != NULL) {
            switchStateBetweenRowOrColumnMajor(encryptedState);
            addKey(paddedText+i, encryptedState);     // XORing next textBlock with the current encrypted state for CBC mode
        }

        free(encryptedState); // Freeing the previous allocated memory to the encryptedState Pointer so that pointer can be used to point to new location

        encryptedState = AES_cipher(paddedText+i, key, aesType);
        // Copying the Encrypted State to the Final Encrypted Text
        memcpy(encryptedText+i, encryptedState, 16);

    }

    char* encryptedHexStr = bytesToHexString(encryptedText, textLength);

    // Cleanup
    free(iv);
    free(key);
    free(encryptedState);
    free(paddedText);
    free(encryptedText);

    return encryptedHexStr;
}

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
EXPORT char* AES_decrypt (char* encryptedHexString, char* keyHexStr, char* IVHexStr, AES_type aesType) {
    uint8_t* encryptedText = hexStringToByteArray(encryptedHexString);
    size_t textLen = strlen(encryptedText);
    uint8_t* key = hexStringToByteArray(keyHexStr);
    uint8_t* iv = hexStringToByteArray(IVHexStr);
    uint8_t currIv[16+1];

    // Allocating the Memory for the Decrypted Text
    uint8_t* decryptedText = (uint8_t*) calloc(textLen+1, sizeof(uint8_t) );
    
    // Storing the 16 byte decrypted State
    uint8_t* decryptedState = NULL;
    
    // Main Decryption Rounds
    for (int i = textLen - 16; i>=0;i-=16) {
        // Freeing the previous memory allocated to the decryptedState so that pointer can be reused for next memory allocation
        free(decryptedState);
        // Decrypting Current State Block
        decryptedState = AES_invCipher( (uint8_t*)encryptedText+i, key, aesType);

        // For CBC Mode
        if (iv != NULL) {
            // Getting the curr IV
            if (i < 16) {
                memcpy(currIv, iv, 16);
            }
            else {
                memcpy(currIv, (uint8_t*)encryptedText+(i-16), 16);
            }

            // XORing the state with the current IV
            switchStateBetweenRowOrColumnMajor(currIv);   // Converting IV to Column Major to perform AES operations
            addKey( (uint8_t*)decryptedState, currIv);

        }        

        
        // Copying decrypted State to the final decrypted Text
        memcpy( (uint8_t*)&decryptedText[i], decryptedState, 16);

    }

    // Removing Padding from the text
    removePadding(decryptedText, 16);
    
    /*  Cleanup */
    free(iv);
    free(key);
    free(encryptedText);
    free(decryptedState);

    return( (char*) decryptedText);

}


