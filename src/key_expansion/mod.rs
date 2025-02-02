/// This module implements AES key expansion using Fully Homomorphic Encryption (FHE).
/// It defines the necessary constants, such as round constants (RCON), and utilizes encrypted bytes
/// (FheUint8) to perform the AES key expansion securely. The key expansion process applies operations
/// like cyclic shifting, S-Box substitution, and XOR with round constants while keeping all computations
/// encrypted, ensuring the privacy of the key throughout the process. The code also leverages parallelism
/// using the Rayon library to speed up S-Box substitutions.
///
/// The `key_expansion_fhe` function performs the AES key expansion and encrypts the expanded key for secure use in AES encryption.
use crate::{get_match_values, SBOX};
use rayon::prelude::*;
use std::time::Instant;
use tfhe::{prelude::FheTrivialEncrypt, FheUint, FheUint8, FheUint8Id};

/// Round constants (RCON) used in AES key expansion.
/// These constants are used in the key schedule core function to introduce non-linearity
/// and ensure key uniqueness across different rounds.
///
/// The values follow the AES key expansion specification:
/// - RCON[0] is unused (0x00).
/// - RCON[1] to RCON[10] correspond to the first 10 rounds of AES key expansion.
/// - Each value is derived from powers of 2 in the finite field GF(2^8).
///
/// These constants help in the generation of round keys, ensuring cryptographic security.
const R_CONSTANTS: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

/// Expands a 128-bit AES key (16 bytes) into a 176-byte expanded key using Fully Homomorphic Encryption (FHE).
/// This function follows the AES key expansion process while applying FHE operations on encrypted bytes.
///
/// # Arguments
/// * `key` - A reference to an array of 16 encrypted bytes (FheUint8) representing the initial AES key.
/// * `expanded_key` - A mutable reference to an array of 176 encrypted bytes to store the expanded key.
pub fn key_expansion_fhe(key: &[FheUint8; 16], expanded_key: &mut [FheUint8; 176]) {
    // Start measuring time for key expansion
    let key_expansion_time = Instant::now();

    // Copy the initial 16-byte key to the beginning of the expanded key array
    expanded_key[0..16].clone_from_slice(&key[..]);

    let mut i = 16usize; // Track the current index in expanded_key

    // Temporary storage for processing 4 bytes at a time
    let mut temp: [FheUint8; 4] = [
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
    ];

    // Retrieve the precomputed match values used for S-Box substitution
    let match_values = get_match_values();

    // Continue expanding the key until we reach 176 bytes
    while i < 176 {
        // Copy the last 4 bytes of the expanded key into temp
        temp.clone_from_slice(&expanded_key[i - 4..i]);

        // Every 16 bytes, perform key schedule core transformations
        if i % 16 == 0 {
            // Rotate temp left (cyclic shift of 1 byte)
            temp.rotate_left(1);

            // Apply S-Box substitution to each byte in parallel
            temp.par_iter_mut().for_each(|byte| {
                let (result, _): (FheUint8, _) = byte.match_value(&match_values).unwrap();
                *byte = result;
            });

            // XOR the first byte with the round constant (RC)
            temp[0] ^= R_CONSTANTS[i / 16];
        }

        // Perform key expansion by XORing with the corresponding previous key bytes
        for j in 0..4 {
            expanded_key[i + j] = expanded_key[i - 16 + j].clone() ^ temp[j].clone();
        }

        // Move to the next block of 4 bytes
        i += 4;
    }

    // Calculate and print the total time taken for key expansion
    let key_expansion_duration = key_expansion_time.elapsed().as_secs();
    println!("AES key expansion took: {} seconds", key_expansion_duration);
}
