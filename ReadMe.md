# AES made easy for C

This is my implementation of the Advanced Encryption Scheme (AES) in C.
An easy to use library with functions which can be readily integrated into your project.


## What is AES?

The AES is a symetric key cryptographic algorithm and is the standard algorithm known for its robust security and efficiency. It operates on blocks of data and employs a series of substitution, permutation, and mixing operations performed through multiple rounds. AES supports key lengths of 128, 192, or 256 bits, with the choice of key length influencing its strength.

The algorithm's strength lies in its resistance to various cryptographic attacks, making it a cornerstone for secure data transmission and storage across a wide range of applications.

For more information about AES encryption see [here](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

## Steps in AES

The key steps in Advanced Encryption Scheme are : 
1. **Key Expansion**
Expanding the original Key (128/192/256 bits) to generate all the required Round Keys for Encryption. The number of rounds depends on the original key-length. 
- *AES_128* : 11 Rounds
- *AES_192* : 13 Rounds
- *AES_256* : 15 Rounds

See [here](http://www.crypto-it.net/eng/symmetric/aes.html) for detailed information about AES Key Expansion.

2. **Creating a State Matrix**
The input text block has to be mapped to a 4 x 4 State Matrix in order to perform the AES operations on it. Each text block has a fixed size of 16 bytes.

```C
uint8_t text[16] = {0x00, 0x01, 0x02, 0x03, .... 0x0D, 0x0E, 0x0F};

// The Above text is mapped to : 
uint8_t stateMatrix[4][4] = {
    {0x00, 0x04, 0x08, 0x0C},
    {0x01, 0x05, 0x09, 0x0D},
    {0x02, 0x06, 0x0A, 0x0E},
    {0x03, 0x07, 0x0B, 0x0F}
};
```

3. **Adding the Round Key**
For each round of the AES encryption we XOR the Round Key with the State Matrix. This makes the encryption dependent on the input Key. All the required Round Keys were already genrated in the Key Expansion part.

4. **Substitute Bytes**
Each Byte in the State Matrix is Substituted using a 16 x 16 substitute table.
![Substitute Box]()
For more information about Rijndael's Substitute Box click [here](https://en.wikipedia.org/wiki/Rijndael_S-box).

5. **Shift Rows**
Each row in the State Matrix is Rotated Left a different number of times. This provides diffusion in our encryption algorithm. 
![Rotate Rows Image]() 

6. **Mix Columns**
The Mix Columns step does a matrix Multiplication of each column of the State Matrix with a fixed 4x4 matrix to get the columns for the resulting State Matrix.

*Note that the matrix multiplication is done in the finite field of GF(2^8). For more information about Finite Fields click [here](https://mathworld.wolfram.com/FiniteField.html).*
## Testing
The usage of all the neccessary encryption and decryption functions are provided in the *aesTest.c* file.

First we need to craete a DLL file which will be linked to our main project. 

Build the DLL file using GCC with command : 
```bash
gcc aes.c -shared -o aes.dll
```

Then include the *aes.h* header file in your project, and while building your project link the DLL to use the functions.

To run the *aesTest.c* file run the following commands : 
```bash
gcc aesTest.c -o aesTest -L/path_To_Folder_Where_Dll_Is_kept -l aes
    
./aesTest
```