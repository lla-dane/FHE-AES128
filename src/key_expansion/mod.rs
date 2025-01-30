use std::time::Instant;

#[macro_use]
use crate::log;
use crate::{get_match_values, SBOX};
use rayon::prelude::*;
use tfhe::{prelude::FheTrivialEncrypt, FheUint, FheUint8, FheUint8Id};

const R_CONSTANTS: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

// Expands the key into multiple round keys.
// Nk = 4 as key = 128
// 10 passes * 16 bytes + 16 bytes = 176

pub fn key_expansion_fhe(key: &[FheUint8; 16], expanded_key: &mut [FheUint8; 176]) {
    let key_expansion_time = Instant::now();

    expanded_key[0..16].clone_from_slice(&key[..]); // Copy the initial key
    let mut i = 16usize;

    // Temporary array for processing
    let mut temp: [FheUint8; 4] = [
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
    ];

    let match_values = get_match_values();

    while i < 176 {
        // Copy the last 4 bytes into temp
        temp.clone_from_slice(&expanded_key[i - 4..i]);

        if i % 16 == 0 {
            // Rotate temp left
            temp.rotate_left(1);

            // Apply S-Box in parallel
            temp.par_iter_mut().for_each(|byte| {
                let (result, _): (FheUint8, _) = byte.match_value(&match_values).unwrap();
                *byte = result;
            });

            // XOR the first byte with the round constant
            temp[0] ^= R_CONSTANTS[i / 16];
        }

        // Parallelize the XOR operation for the 4 bytes
        for j in 0..4 {
            expanded_key[i + j] = expanded_key[i - 16 + j].clone() ^ temp[j].clone();
        }

        i += 4; // Increment by 4 as we're processing 4 bytes at a time
    }

    let key_expansion_duration = key_expansion_time.elapsed().as_secs();
    println!("AES key expansion took: {} seconds", key_expansion_duration);
}


