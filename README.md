# Camellia Cipher
CS4021D: Number Theory and Cryptography - Assignment 2

### Introduction

The Camellia cipher is a symmetric key block cipher that operates on fixed-size blocks of data. The cipher uses an 18-round Feistel architecture for 128-bit keys. The use of S-boxes (substitution boxes) introduce non-linearities in the encryption process.

![Feistel Network](/feistel.png)

### Known issues:
- The algorithm fails when the key size is greater than 128 bits.  
- Algorithm accepts any size of key less than 128 bits no matter how small it is.  
- Constants are used as they are in the official documentation.  

