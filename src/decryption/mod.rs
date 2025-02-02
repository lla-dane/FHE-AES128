/// This module implements the inverse transformations used in AES decryption with Fully Homomorphic Encryption (FHE).
/// It includes functions to reverse the operations applied during encryption:
/// - `inv_sub_bytes`: Inverse byte substitution using the inverse AES S-Box.
/// - `inv_shift_rows`: Reverses the row shifting of the AES state matrix.
/// - `inv_mix_columns`: Reverses the column mixing using Galois Field multiplication.
///
/// Each operation is parallelized for efficiency using the Rayon library and utilizes FHE to ensure the privacy of the data during decryption.
use crate::encryption::gal_mul_int;
use crate::utils::INV_SBOX;
use rayon::prelude::*;
use std::thread;
use std::time::Duration;
use tfhe::prelude::*;
use tfhe::{FheUint8, MatchValues};

/// Performs the inverse SubBytes transformation in AES decryption using Fully Homomorphic Encryption (FHE).
///
/// This operation applies the inverse S-Box substitution to each byte in the AES state.
/// It is the reverse of the `sub_bytes` function and is used during decryption.
///
/// # Arguments
/// * `state` - A mutable reference to a vector of encrypted bytes (FheUint8), representing the AES state.
///
/// # Behavior
/// - Each byte in the `state` vector is replaced by its corresponding value in the inverse S-Box (`INV_SBOX`).
/// - The substitution is performed using a **lookup table** stored in `INV_SBOX`.
/// - Processing is **parallelized** for efficiency using `par_iter_mut()`.
pub fn inv_sub_bytes(state: &mut Vec<FheUint8>) {
    // Create a mapping of byte values (0-255) to their corresponding inverse S-Box values.
    let match_vector: Vec<(u8, u8)> = (0u8..=255u8)
        .map(|x| (x, INV_SBOX[x as usize])) // Map input byte to its inverse S-Box value
        .collect();

    // Initialize the match values structure for lookup
    let match_values = MatchValues::new(match_vector).unwrap();

    // Apply inverse S-Box substitution to each byte in the state in parallel
    state
        .par_iter_mut() // Use a parallel iterator for efficiency
        .enumerate() // Include index for potential debugging/logging
        .for_each(|(index, i)| {
            (*i, _) = i.match_value(&match_values).unwrap(); // Perform secure lookup and update value
        });
}

/// Performs the inverse ShiftRows transformation in AES decryption using Fully Homomorphic Encryption (FHE).
///
/// This operation reverses the row shifting performed in the `shift_rows` function during encryption.
/// It cyclically shifts each row of the state matrix to the **right**, restoring the original order.
///
/// # Arguments
/// * `state` - A mutable reference to a vector of encrypted bytes (FheUint8), representing the AES state.
///
/// # Behavior
/// - The **first row** remains unchanged.
/// - The **second row** shifts **one position to the right**.
/// - The **third row** shifts **two positions to the right**.
/// - The **fourth row** shifts **three positions to the right**.
/// - Processing is **parallelized** for efficiency using [`par_iter_mut()`].
pub fn inv_shift_rows(state: &mut Vec<FheUint8>) {
    let temp: Vec<FheUint8> = state.clone(); // Create a copy of the current state for reference

    // Apply inverse row shifts in parallel
    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = match i {
            0 => temp[0].clone(),
            1 => temp[13].clone(),
            2 => temp[10].clone(),
            3 => temp[7].clone(),
            4 => temp[4].clone(),
            5 => temp[1].clone(),
            6 => temp[14].clone(),
            7 => temp[11].clone(),
            8 => temp[8].clone(),
            9 => temp[5].clone(),
            10 => temp[2].clone(),
            11 => temp[15].clone(),
            12 => temp[12].clone(),
            13 => temp[9].clone(),
            14 => temp[6].clone(),
            15 => temp[3].clone(),
            _ => unreachable!(),
        };
    });
}

/// Performs the inverse MixColumns transformation on the given AES state.
///
/// This function modifies the `state` vector in place, applying the inverse
/// MixColumns operation used in AES decryption. It operates on a 4x4 matrix
/// of bytes, treating the state as a column-major order array.
///
/// # Parameters
/// - `state`: A mutable reference to a vector of `FheUint8` values representing
///   the AES state. The vector should have exactly 16 elements.
///
/// # Details
/// - The transformation is applied independently to each of the four columns.
/// - Each column undergoes matrix multiplication in the Galois Field GF(2^8)
///   using the fixed inverse MixColumns matrix:
///
///   ```text
///   | 0E 0B 0D 09 |
///   | 09 0E 0B 0D |
///   | 0D 09 0E 0B |
///   | 0B 0D 09 0E |
///   ```
///
/// - Parallel iteration (`par_iter_mut`) is used for performance optimization.
///
/// # Assumptions
/// - The input vector `state` must contain exactly 16 elements.
/// - `gal_mul_int` performs multiplication in GF(2^8).
///
/// # Panics
/// - The function will panic if `state` does not have exactly 16 elements.
/// - The `_ => unreachable!()` branch ensures that the match statement only
///   works for valid indices within the range [0, 15].
pub fn inv_mix_columns(state: &mut Vec<FheUint8>) {
    let temp = state.clone();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = match i {
            0 => {
                gal_mul_int(temp[0].clone(), 0x0e)
                    ^ gal_mul_int(temp[1].clone(), 0x0b)
                    ^ gal_mul_int(temp[2].clone(), 0x0d)
                    ^ gal_mul_int(temp[3].clone(), 0x09)
            }
            1 => {
                gal_mul_int(temp[0].clone(), 0x09)
                    ^ gal_mul_int(temp[1].clone(), 0x0e)
                    ^ gal_mul_int(temp[2].clone(), 0x0b)
                    ^ gal_mul_int(temp[3].clone(), 0x0d)
            }
            2 => {
                gal_mul_int(temp[0].clone(), 0x0d)
                    ^ gal_mul_int(temp[1].clone(), 0x09)
                    ^ gal_mul_int(temp[2].clone(), 0x0e)
                    ^ gal_mul_int(temp[3].clone(), 0x0b)
            }
            3 => {
                gal_mul_int(temp[0].clone(), 0x0b)
                    ^ gal_mul_int(temp[1].clone(), 0x0d)
                    ^ gal_mul_int(temp[2].clone(), 0x09)
                    ^ gal_mul_int(temp[3].clone(), 0x0e)
            }
            4 => {
                gal_mul_int(temp[4].clone(), 0x0e)
                    ^ gal_mul_int(temp[5].clone(), 0x0b)
                    ^ gal_mul_int(temp[6].clone(), 0x0d)
                    ^ gal_mul_int(temp[7].clone(), 0x09)
            }
            5 => {
                gal_mul_int(temp[4].clone(), 0x09)
                    ^ gal_mul_int(temp[5].clone(), 0x0e)
                    ^ gal_mul_int(temp[6].clone(), 0x0b)
                    ^ gal_mul_int(temp[7].clone(), 0x0d)
            }
            6 => {
                gal_mul_int(temp[4].clone(), 0x0d)
                    ^ gal_mul_int(temp[5].clone(), 0x09)
                    ^ gal_mul_int(temp[6].clone(), 0x0e)
                    ^ gal_mul_int(temp[7].clone(), 0x0b)
            }
            7 => {
                gal_mul_int(temp[4].clone(), 0x0b)
                    ^ gal_mul_int(temp[5].clone(), 0x0d)
                    ^ gal_mul_int(temp[6].clone(), 0x09)
                    ^ gal_mul_int(temp[7].clone(), 0x0e)
            }
            8 => {
                gal_mul_int(temp[8].clone(), 0x0e)
                    ^ gal_mul_int(temp[9].clone(), 0x0b)
                    ^ gal_mul_int(temp[10].clone(), 0x0d)
                    ^ gal_mul_int(temp[11].clone(), 0x09)
            }
            9 => {
                gal_mul_int(temp[8].clone(), 0x09)
                    ^ gal_mul_int(temp[9].clone(), 0x0e)
                    ^ gal_mul_int(temp[10].clone(), 0x0b)
                    ^ gal_mul_int(temp[11].clone(), 0x0d)
            }
            10 => {
                gal_mul_int(temp[8].clone(), 0x0d)
                    ^ gal_mul_int(temp[9].clone(), 0x09)
                    ^ gal_mul_int(temp[10].clone(), 0x0e)
                    ^ gal_mul_int(temp[11].clone(), 0x0b)
            }
            11 => {
                gal_mul_int(temp[8].clone(), 0x0b)
                    ^ gal_mul_int(temp[9].clone(), 0x0d)
                    ^ gal_mul_int(temp[10].clone(), 0x09)
                    ^ gal_mul_int(temp[11].clone(), 0x0e)
            }
            12 => {
                gal_mul_int(temp[12].clone(), 0x0e)
                    ^ gal_mul_int(temp[13].clone(), 0x0b)
                    ^ gal_mul_int(temp[14].clone(), 0x0d)
                    ^ gal_mul_int(temp[15].clone(), 0x09)
            }
            13 => {
                gal_mul_int(temp[12].clone(), 0x09)
                    ^ gal_mul_int(temp[13].clone(), 0x0e)
                    ^ gal_mul_int(temp[14].clone(), 0x0b)
                    ^ gal_mul_int(temp[15].clone(), 0x0d)
            }
            14 => {
                gal_mul_int(temp[12].clone(), 0x0d)
                    ^ gal_mul_int(temp[13].clone(), 0x09)
                    ^ gal_mul_int(temp[14].clone(), 0x0e)
                    ^ gal_mul_int(temp[15].clone(), 0x0b)
            }
            15 => {
                gal_mul_int(temp[12].clone(), 0x0b)
                    ^ gal_mul_int(temp[13].clone(), 0x0d)
                    ^ gal_mul_int(temp[14].clone(), 0x09)
                    ^ gal_mul_int(temp[15].clone(), 0x0e)
            }
            _ => unreachable!(),
        };
    });
}
