/*!
 * # Fully Homomorphic Encryption (FHE) Based AES-128 Implementation
 *
 * ## Overview
 * This Rust program implements AES-128 encryption and decryption using
 * Fully Homomorphic Encryption (FHE). It enables secure computations on encrypted
 * data without the need for decryption, preserving privacy in sensitive operations.
 *
 * ## Features
 * - AES-128 encryption and decryption using FHE
 * - Key expansion using FHE operations
 * - Performance measurement for encryption and decryption
 * - Command-line interface for specifying encryption key, IV, and output count
 *
 * ## Dependencies
 * - `tfhe` for Fully Homomorphic Encryption operations
 * - `aes` for standard AES encryption (used for verification)
 * - `clap` for command-line argument parsing
 * - `rayon` for parallel computation distribution
 * - `rand` for random number generation in tests
 *
 * ## Usage
 * The program encrypts a specified number of blocks using AES-128 in an FHE environment
 * and then decrypts them to verify correctness. The execution time for both encryption
 * and decryption is measured.
 *
 * Example command:
 * ```
 * cargo run --release -- -n 3 -k 000102030405060708090a0b0c0d0e0f -i 00112233445566778899aabbccddeeff
 * ```
 * This encrypts and decrypts one block using the specified key and IV.
 *
 * ## Testing
 * The implementation includes unit tests for:
 * - AES encryption correctness
 * - AES decryption correctness
 * - AES key expansion process
 *
 * To run the tests:
 * ```
 * cargo test --release --package fhe-aes128 --bin fhe-aes128
 * ```
 */

#![allow(unused)]
mod decryption;
mod encryption;
mod key_expansion;
pub mod utils;

use std::time::Instant;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use clap::Parser;
use decryption::{inv_mix_columns, inv_shift_rows, inv_sub_bytes};
use encryption::*;
use key_expansion::*;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint, FheUint8, FheUint8Id, MatchValues,
};
use utils::{hex_to_u8_array, increment_counter, SBOX};

fn get_match_values() -> MatchValues<u8> {
    let match_vector = (0u8..=255u8).map(|x| (x, SBOX[x as usize])).collect();

    MatchValues::new(match_vector).unwrap()
}

/// Encrypts a single block of data using AES encryption with Fully Homomorphic Encryption (FHE).
///
/// # Arguments
///
/// * `input` - A vector of `FheUint8` representing the plaintext input block.
/// * `output` - A mutable reference to an array of `FheUint8` where the encrypted output block will be stored.
/// * `expanded_key` - A slice of `FheUint<FheUint8Id>` representing the expanded AES key.
///
/// # Description
///
/// This function performs the AES encryption process on a single block of data. It includes
/// the initial round key addition, followed by 9 rounds of sub bytes, shift rows, mix columns,
/// and adding the round keys, and a final round without mix columns.
fn aes_encrypt_block(
    input: &Vec<FheUint8>,
    output: &mut [FheUint8; 16],
    expanded_key: &[FheUint<FheUint8Id>; 176],
) {
    let mut state = input.clone();

    // Initial round key addition
    add_blocks(&mut state, &expanded_key[0..16]);

    // Perform 9 rounds of encryption
    for round in 1..10 {
        sub_bytes(&mut state); // Sub bytes
        shift_rows(&mut state); // Shift rows
        mix_columns(&mut state); // Mix columns
        add_blocks(&mut state, &expanded_key[round * 16..(round + 1) * 16]); // Add round key
    }

    // Final round (without mix columns)
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_blocks(&mut state, &expanded_key[160..176]); // Add final round key

    // Copy the encrypted state to the output
    output.clone_from_slice(&state);
}

/// Decrypts a single block of data using AES decryption with Fully Homomorphic Encryption (FHE).
///
/// # Arguments
///
/// * `input` - A vector of `FheUint8` representing the encrypted input block.
/// * `output` - A mutable reference to an array of `FheUint8` where the decrypted output block will be stored.
/// * `expanded_key` - A slice of `FheUint<FheUint8Id>` representing the expanded AES key.
///
/// # Description
///
/// This function performs the AES decryption process on a single block of data. It uses the inverse
/// operations of the AES encryption process, including inverse shift rows, inverse sub bytes, and
/// inverse mix columns, along with adding the round keys in reverse order.
fn aes_decrypt_block(
    input: &Vec<FheUint8>,
    output: &mut [FheUint8; 16],
    expanded_key: &[FheUint<FheUint8Id>; 176],
) {
    let mut state = input.clone();

    // Initial round key addition
    add_blocks(&mut state, &expanded_key[160..176]);

    // Perform 9 rounds of decryption
    for round in (1..10).rev() {
        inv_shift_rows(&mut state); // Inverse shift rows
        inv_sub_bytes(&mut state); // Inverse sub bytes
        add_blocks(&mut state, &expanded_key[round * 16..(round + 1) * 16]); // Add round key
        inv_mix_columns(&mut state); // Inverse mix columns
    }

    // Final round (without inverse mix columns)
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_blocks(&mut state, &expanded_key[0..16]); // Add initial round key

    // Copy the decrypted state to the output
    output.clone_from_slice(&state);
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Struct representing the command line arguments for the application.
struct Args {
    /// The number of outputs to generate. Defaults to 1 if not specified.
    #[arg(short, long, default_value_t = 1)]
    number_of_outputs: u32,

    /// The initialization vector (IV) for AES encryption. This is a required argument.
    #[arg(short, long)]
    iv: String,

    /// The encryption key for AES encryption. This is a required argument.
    #[arg(short, long)]
    key: String,
}
// cargo run --release -- -n 1 -k 000102030405060708090a0b0c0d0e0f -i 00112233445566778899aabbccddeeff

/// This program performs Fully Homomorphic Encryption (FHE) based AES encryption and decryption.
/// It takes an initialization vector (IV) and a key as input, encrypts a specified number of
/// outputs using AES-128 in an FHE setting, and then decrypts them to verify correctness.
/// The program also measures and prints the time taken for encryption and decryption.
fn main() {
    let args = Args::parse();

    // Convert the iv and key to an array of u8
    let iv = hex_to_u8_array(&args.iv).unwrap();
    let key = hex_to_u8_array(&args.key).unwrap();

    // Create the AES128 encryptred ciphertext using standard AES128 crate
    // for final verification
    let mut expected_state = iv.clone();
    let aes_cipher = Aes128::new((&key).into());
    aes_cipher.encrypt_block((&mut expected_state).into());

    // Increment the counter for required number of outputs
    let mut counters_encryption: Vec<[u8; 16]> = vec![iv];

    for _ in 0..(args.number_of_outputs - 1) {
        let incremented_iv = increment_counter(&iv);
        counters_encryption.push(incremented_iv);
    }

    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    // Distributing the server key to all the threads
    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    // Generating the FHE-AES key from the hex string input
    let key_fhe: [FheUint<FheUint8Id>; 16] =
        std::array::from_fn(|index| FheUint8::encrypt(key[index], &cks));

    let mut expanded_key: [FheUint<FheUint8Id>; 176] =
        std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

    // ----------FHE-AES-KEY-EXPANSION-------------
    key_expansion_fhe(&key_fhe, &mut expanded_key);

    let mut output_encryption: Vec<[FheUint8; 16]> =
        vec![std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks))];

    // Measure the time of computation
    let computation_time = Instant::now();

    // ------FHE-AES-ENCRYPTION for specified number_of_outputs-------
    for i in 0..(args.number_of_outputs) as usize {
        let mut _output_encryption: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        let input: Vec<FheUint8> = counters_encryption[i]
            .iter()
            .map(|x| FheUint8::encrypt(*x, &cks))
            .collect();

        if i == 0 {
            aes_encrypt_block(&input, &mut output_encryption[i], &expanded_key);
            continue;
        }

        aes_encrypt_block(&input, &mut _output_encryption, &expanded_key);
        output_encryption.push(_output_encryption);
    }

    // -------FHE-AES-DECRYPTION for specified number_of_outputs-------
    let mut output_decryption: Vec<[FheUint8; 16]> =
        vec![std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks))];

    for i in 0..(args.number_of_outputs) as usize {
        let mut _output_decryption: [FheUint8; 16] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        if i == 0 {
            aes_decrypt_block(
                &output_encryption[i].clone().into(),
                &mut output_decryption[i],
                &expanded_key,
            );
            continue;
        }

        aes_decrypt_block(
            &output_encryption[i].clone().into(),
            &mut _output_decryption,
            &expanded_key,
        );

        output_decryption.push(_output_decryption);
    }

    let computation_duration = computation_time.elapsed().as_secs();

    // Cross checking the AES outputs
    for i in 0..16 {
        let result: u8 = output_encryption[0][i].decrypt(&cks);
        assert_eq!(result, expected_state[i]);
    }

    for i in 0..16 {
        let result: u8 = output_decryption[0][i].decrypt(&cks);
        assert_eq!(result, iv[i]);
    }

    println!(
        "AES of {} outputs took {} seconds",
        output_decryption.len(),
        computation_duration
    );
}

#[cfg(test)]
/// This module contains tests for AES encryption, decryption, and key expansion using Fully Homomorphic Encryption (FHE).
///
/// # Functions
///
/// - `generate_random_hex_string`: Generates a random 16-byte hexadecimal string.
///
/// - `aes_encryption`: Tests AES encryption by generating a random IV and key, encrypting a block, and verifying the result.
///
/// - `aes_decryption`: Tests AES decryption by generating a random IV and key, decrypting a block, and verifying the result.
///
/// - `aes_key_expansion`: Tests AES key expansion by generating a random key and expanding it using FHE.
///
/// # Usage
///
/// To run the tests with --release flag, use the following commands:
///
/// ```sh
/// cargo test --release --package fhe-aes128 --bin fhe-aes128 -- tests::aes_encryption --exact --show-output
/// cargo test --release --package fhe-aes128 --bin fhe-aes128 -- tests::aes_decryption --exact --show-output
/// cargo test --release --package fhe-aes128 --bin fhe-aes128 -- tests::aes_key_expansion --exact --show-output
/// ```
mod tests {
    use rand::Rng;
    use std::{fs::File, io::Write, time::Instant};

    use super::*;

    fn generate_random_hex_string() -> String {
        let mut rng = rand::thread_rng();
        (0..16)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect()
    }

    #[test]
    fn aes_encryption() {
        let encryption_start = Instant::now();

        let iv = hex_to_u8_array(&generate_random_hex_string()).unwrap();
        let key = hex_to_u8_array(&generate_random_hex_string()).unwrap();

        let mut expected_state = iv.clone();
        let aes_cipher = Aes128::new((&key).into());
        aes_cipher.encrypt_block((&mut expected_state).into());

        let number_of_outputs = rand::thread_rng().gen_range(1..=8) as usize;

        let mut counters_encryption: Vec<[u8; 16]> = vec![iv];
        for _ in 0..(number_of_outputs - 1) {
            let incremented_iv = increment_counter(&iv);
            counters_encryption.push(incremented_iv);
        }

        let config = ConfigBuilder::default().build();
        let (cks, sks) = generate_keys(config);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);

        let key_fhe: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|index| FheUint8::encrypt(key[index], &cks));

        let mut expanded_key: [FheUint<FheUint8Id>; 176] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        key_expansion_fhe(&key_fhe, &mut expanded_key);

        let mut output_encryption: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        for i in 0..number_of_outputs {
            let mut _output_encryption: [FheUint<FheUint8Id>; 16] =
                std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

            let input: Vec<FheUint8> = counters_encryption[i]
                .iter()
                .map(|x| FheUint8::encrypt(*x, &cks))
                .collect();

            if i == 0 {
                aes_encrypt_block(&input, &mut output_encryption, &expanded_key);
                continue;
            }

            aes_encrypt_block(&input, &mut _output_encryption, &expanded_key);
        }

        let encryption_duration = encryption_start.elapsed().as_secs();

        for i in 0..16 {
            let result: u8 = output_encryption[i].decrypt(&cks);
            assert_eq!(result, expected_state[i]);
        }

        println!(
            "AES encryption of {} outputs took {} seconds",
            number_of_outputs, encryption_duration
        );
    }

    #[test]
    fn aes_decryption() {
        let decryption_start = Instant::now();

        let iv = hex_to_u8_array(&generate_random_hex_string()).unwrap();
        let key = hex_to_u8_array(&generate_random_hex_string()).unwrap();

        let mut expected_state = iv.clone();
        let aes_cipher = Aes128::new((&key).into());
        aes_cipher.encrypt_block((&mut expected_state).into());

        let number_of_outputs = rand::thread_rng().gen_range(1..=8) as usize;

        let mut counters_decryption: Vec<[u8; 16]> = vec![expected_state];
        for _ in 0..(number_of_outputs - 1) {
            let incremented_exepcted_state = increment_counter(&expected_state);
            counters_decryption.push(incremented_exepcted_state);
        }

        let config = ConfigBuilder::default().build();
        let (cks, sks) = generate_keys(config);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);

        let key_fhe: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|index| FheUint8::encrypt(key[index], &cks));

        let mut expanded_key: [FheUint<FheUint8Id>; 176] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        key_expansion_fhe(&key_fhe, &mut expanded_key);

        let mut output_decryption: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        for i in 0..number_of_outputs {
            let mut _output_decryption: [FheUint<FheUint8Id>; 16] =
                std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

            let input: Vec<FheUint8> = counters_decryption[i]
                .iter()
                .map(|x| FheUint8::encrypt(*x, &cks))
                .collect();

            if i == 0 {
                aes_decrypt_block(&input, &mut output_decryption, &expanded_key);
                continue;
            }

            aes_decrypt_block(&input, &mut _output_decryption, &expanded_key);
        }

        let decryption_duration = decryption_start.elapsed().as_secs();

        for i in 0..16 {
            let result: u8 = output_decryption[i].decrypt(&cks);
            assert_eq!(result, iv[i]);
        }

        println!(
            "AES decryption of {} outputs took {} seconds",
            number_of_outputs, decryption_duration
        );
    }

    #[test]
    fn aes_key_expansion() {
        let config = ConfigBuilder::default().build();
        let (cks, sks) = generate_keys(config);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);

        let key = hex_to_u8_array(&generate_random_hex_string()).unwrap();
        let key_fhe = std::array::from_fn(|index| FheUint8::encrypt(key[index], &cks));

        let mut expanded_key: [FheUint<FheUint8Id>; 176] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &cks));

        key_expansion_fhe(&key_fhe, &mut expanded_key);
    }
}
