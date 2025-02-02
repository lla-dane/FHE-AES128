# Homomorphic AES-128 Implementation

## Overview

This Rust program implements AES-128 encryption and decryption using Fully Homomorphic Encryption (FHE). It enables secure computations on encrypted data without the need for decryption, preserving privacy in sensitive operations.

The implementation is split into two main components:

1. Key Expansion

2. Encryption/Decryption

## System design
![fhe_aes128_sys](https://github.com/user-attachments/assets/89e5b94c-4f7d-49db-877b-fe64033d76a7)

## System Requirements

Rust (nightly version specified in toolchain.txt)

## Installation

Clone the repository and navigate to the project directory:

```bash
git clone <repo-url>
cd fhe-aes128
```

Build/test the project:

```bash
cargo build --release
cargo test
```

## How to run the provided executable ?

### Usage:

./fhe-aes128 [OPTIONS]

```bash
./fhe-aes128 [OPTIONS]

Options:
--number-of-outputs <N>     Specify the number of outputs (default: 1).
--iv <IV>                   Initialization vector for AES.
--key <KEY>                 128-bit AES key (32 hexadecimal characters).
```

### From source

```bash
./target/release/fhe-aes128 --number-of-outputs <N> --iv <IV> --key <KEY>
```

Standard example:

```bash
cargo run --release -- -n 1 -k 000102030405060708090a0b0c0d0e0f -i 00112233445566778899aabbccddeeff

./target/release/fhe-aes128 --number-of-outputs 10 --iv 00112233445566778899AABBCCDDEEFF --key 000102030405060708090A0B0C0D0E0F
```

### From executable

```bash
./fhe-aes128 --number-of-outputs <N> --iv <IV> --key <KEY>

./fhe-aes128 --number-of-outputs 10 --iv 00112233445566778899AABBCCDDEEFF --key 000102030405060708090A0B0C0D0E0F
```

## How to use our FHE implementation ?

### The implementation consists of 3 major modules:

### 1. Key-Expansion

This module implements AES key expansion using Fully Homomorphic Encryption (FHE), defining necessary constants like `round constants` (RCON) and using encrypted bytes (FheUint8) to securely perform the AES key expansion, applying operations such as `cyclic shifting`,`S-Box substitution`, and XOR with round constants while ensuring the privacy of the key throughout the process, and leveraging parallelism via the Rayon library to speed up S-Box substitutions.

#### To perform FHE AES128 key-expansion as a separate task, execute the following function with correct parameter types, and the `expanded_key` will store the required output.

```rust
pub fn key_expansion_fhe(key: &[FheUint8; 16], expanded_key: &mut [FheUint8; 176])
```

### 2. Encryption

This module implements key transformations in AES encryption using Fully Homomorphic Encryption (FHE), including operations like `AddRoundKey` (XOR), `SubBytes` (S-Box substitution), `ShiftRows` (row shifting), and `MixColumns` (Galois Field multiplication), with each transformation optimized for performance through parallelism using the Rayon library and FHE techniques.

#### To perform FHE AES128 encryption as a separate task, execute the following function with correct parameter types, and the `output` will store the required FHE-AES128 encrypted ciphertext.

```rust
fn aes_encrypt_block(
    input: &Vec<FheUint8>,
    output: &mut [FheUint8; 16],
    expanded_key: &[FheUint<FheUint8Id>; 176],
)
```

### 3. Decryption

This module implements the inverse transformations used in AES decryption utilizing Fully Homomorphic Encryption (FHE). It defines three key operations: `inv_sub_bytes` (inverse byte substitution using the inverse S-Box), `inv_shift_rows` (inverse row shifting to restore the original matrix configuration), and `inv_mix_columns` (inverse mixing of columns with Galois Field multiplication). These functions work in parallel using the Rayon library to optimize performance and leverage FHE to maintain data privacy during the decryption process.

#### To perform FHE AES128 encryption as a separate task, execute the following function with correct parameter types, and the `output` will store the required FHE-AES128 decrypted plaintext.

```rust
fn aes_decrypt_block(
    input: &Vec<FheUint8>,
    output: &mut [FheUint8; 16],
    expanded_key: &[FheUint<FheUint8Id>; 176],
)
```

## Acknowledgments

- TFHE-rs library for enabling Fully Homomorphic Encryption.
- Rayon for parallelism.
- The AES cryptography research community for their invaluable work in secure encryption standards.
