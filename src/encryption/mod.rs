/// This module implements key transformations in the AES encryption process using Fully Homomorphic Encryption (FHE).
/// It includes functions for performing the following operations:
/// - `add_blocks`: Element-wise XOR operation for the AddRoundKey step.
/// - `sub_bytes`: Substitution of bytes using the AES S-Box for the SubBytes transformation.
/// - `shift_rows`: Shifting rows of the AES state matrix for the ShiftRows transformation.
/// - `mix_columns`: Mixing columns of the AES state matrix using Galois Field multiplication for the MixColumns transformation.
/// Each transformation is implemented with parallelism for performance optimization, utilizing the Rayon library and FHE techniques.
use crate::SBOX;
use rayon::prelude::*;
use std::thread;
use std::time::Duration;
use tfhe::prelude::*;
use tfhe::{FheUint8, MatchValues};

/// Performs an element-wise XOR operation between two blocks of encrypted bytes (state and b).
/// This is typically used in AES encryption for the AddRoundKey step.
///
/// # Arguments
/// * `state` - A mutable reference to a vector of encrypted bytes [FheUint8] representing the current state.
/// * `b` - A reference to a slice of encrypted bytes [FheUint8] that will be XORed with the state.
///
/// # Behavior
/// - Each byte in `state` is XORed with the corresponding byte in `b`.
/// - Uses parallel iteration [`par_iter_mut`] for performance optimization.
pub fn add_blocks(state: &mut Vec<FheUint8>, b: &[FheUint8]) {
    state
        .par_iter_mut() // Iterate over `state` in parallel for performance
        .enumerate() // Keep track of index to access corresponding `b` element
        .for_each(|(i, state_elem)| {
            *state_elem ^= b[i].clone(); // Perform XOR operation on each byte
        });
}

/// Performs the SubBytes transformation in AES encryption using Fully Homomorphic Encryption (FHE).
/// Each byte in the state is substituted using the AES S-Box lookup table.
///
/// # Arguments
/// * `state` - A mutable reference to a vector of encrypted bytes [FheUint8] representing the AES state.
///
/// # Behavior
/// - Constructs a matching vector from the AES [S-Box].
/// - Uses [`MatchValues`] to perform a secure substitution of each byte.
/// - Processes elements in parallel for efficiency.
pub fn sub_bytes(state: &mut Vec<FheUint8>) {
    // Create a matching vector using the AES S-Box for byte substitution
    let match_vector: Vec<(u8, u8)> = (0u8..=255u8)
        .map(|x| (x, SBOX[x as usize])) // Map each byte to its S-Box substitution
        .collect();

    // Initialize match values for secure lookup
    let match_values = MatchValues::new(match_vector).unwrap();

    // Apply S-Box substitution in parallel
    state
        .par_iter_mut() // Parallel iterator for efficient processing
        .enumerate() // Include index for potential debugging
        .for_each(|(index, i)| {
            (*i, _) = i.match_value(&match_values).unwrap(); // Substitute byte using S-Box mapping
        });
}

/// Performs the ShiftRows transformation in AES encryption using Fully Homomorphic Encryption (FHE).
/// This operation shifts the rows of the 4x4 AES state matrix to the left by different offsets.
///
/// # Arguments
/// * `state` - A mutable reference to a vector of 16 encrypted bytes (FheUint8), representing the AES state.
///
/// # Behavior
/// - The first row remains unchanged.
/// - The second row shifts left by 1 position.
/// - The third row shifts left by 2 positions.
/// - The fourth row shifts left by 3 positions.
/// - This transformation is performed in parallel for efficiency.
pub fn shift_rows(state: &mut Vec<FheUint8>) {
    // Create a temporary copy of the state to use for reordering
    let temp: Vec<FheUint8> = state.clone();

    // Apply ShiftRows transformation in parallel
    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = match i {
            // First row (unchanged)
            0 => temp[0].clone(),
            1 => temp[5].clone(),
            2 => temp[10].clone(),
            3 => temp[15].clone(),

            // Second row (shift left by 1)
            4 => temp[4].clone(),
            5 => temp[9].clone(),
            6 => temp[14].clone(),
            7 => temp[3].clone(),

            // Third row (shift left by 2)
            8 => temp[8].clone(),
            9 => temp[13].clone(),
            10 => temp[2].clone(),
            11 => temp[7].clone(),

            // Fourth row (shift left by 3)
            12 => temp[12].clone(),
            13 => temp[1].clone(),
            14 => temp[6].clone(),
            15 => temp[11].clone(),

            _ => unreachable!(), // This case should never be reached
        };
    });
}

/// Performs finite field multiplication (Galois Field multiplication) in GF(2^8) using Fully Homomorphic Encryption (FHE).
///
/// This function multiplies two elements in the AES finite field, where:
/// - Addition is performed using XOR.
/// - Multiplication follows the polynomial representation of GF(2^8).
///
/// # Arguments
/// * `a` - An encrypted byte (FheUint8), the first operand.
/// * `b` - A plaintext byte (u8), the second operand.
///
/// # Returns
/// * `FheUint8` - The result of the multiplication in GF(2^8).
pub fn gal_mul(a: FheUint8, b: u8) -> FheUint8 {
    // Initialize the result as 0 in GF(2^8)
    let mut result: FheUint8 = FheUint8::encrypt_trivial(0u8);

    // Copy inputs to mutable variables for processing
    let mut a = a;
    let mut b = b;

    // AES uses the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x1b) for field reduction
    const IRREDUCIBLE_POLY: u8 = 0x1b;

    // Process each bit of `b`, using a multiplication-by-x approach
    while b != 0 {
        // If the least significant bit of `b` is 1, add `a` to the result using XOR (addition in GF(2^8))
        if (b & 1) != 0 {
            result ^= a.clone();
        }

        // Check if the highest bit (x^7) of `a` is set before shifting
        let high_bit_set = (a.clone() & 0x80).ne(0); // Checks if the highest bit is 1

        // Multiply `a` by x (left shift in GF(2^8))
        a <<= 1u8;

        // If `a` overflowed (i.e., its high bit was set), reduce it modulo the irreducible polynomial
        a = (high_bit_set).if_then_else(&(a.clone() ^ IRREDUCIBLE_POLY), &a);

        // Move to the next bit in `b` (divide by x)
        b >>= 1;
    }

    // Return the result of the multiplication
    result
}

/// Performs the MixColumns transformation in AES encryption using Fully Homomorphic Encryption (FHE).
///
/// This operation mixes each column of the AES state matrix by performing matrix multiplication
/// in the Galois Field [GF(2^8)]. The transformation strengthens diffusion by spreading the influence
/// of each input byte over multiple output bytes.
///
/// # Arguments
/// * `state` - A mutable reference to a vector of 16 encrypted bytes [FheUint8], representing the AES state.
///
/// # Behavior
/// - Each column in the AES state matrix is multiplied by a fixed matrix:
/// ```text
/// |  2  3  1  1 |
/// |  1  2  3  1 |
/// |  1  1  2  3 |
/// |  3  1  1  2 |
/// ```
/// - Multiplications in [GF(2^8)] are performed using [`gal_mul()`].
/// - Processing is parallelized for efficiency.
pub fn mix_columns(state: &mut Vec<FheUint8>) {
    // Create a copy of the state to prevent overwriting values prematurely
    let temp = state.clone();

    // Apply MixColumns transformation in parallel
    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = match i {
            // First column transformation
            0 => {
                gal_mul(temp[0].clone(), 2u8)
                    ^ gal_mul(temp[1].clone(), 3u8)
                    ^ temp[2].clone()
                    ^ temp[3].clone()
            }
            1 => {
                temp[0].clone()
                    ^ gal_mul(temp[1].clone(), 2u8)
                    ^ gal_mul(temp[2].clone(), 3u8)
                    ^ temp[3].clone()
            }
            2 => {
                temp[0].clone()
                    ^ temp[1].clone()
                    ^ gal_mul(temp[2].clone(), 2u8)
                    ^ gal_mul(temp[3].clone(), 3u8)
            }
            3 => {
                gal_mul(temp[0].clone(), 3u8)
                    ^ temp[1].clone()
                    ^ temp[2].clone()
                    ^ gal_mul(temp[3].clone(), 2u8)
            }

            // Second column transformation
            4 => {
                gal_mul(temp[4].clone(), 2u8)
                    ^ gal_mul(temp[5].clone(), 3u8)
                    ^ temp[6].clone()
                    ^ temp[7].clone()
            }
            5 => {
                temp[4].clone()
                    ^ gal_mul(temp[5].clone(), 2u8)
                    ^ gal_mul(temp[6].clone(), 3u8)
                    ^ temp[7].clone()
            }
            6 => {
                temp[4].clone()
                    ^ temp[5].clone()
                    ^ gal_mul(temp[6].clone(), 2u8)
                    ^ gal_mul(temp[7].clone(), 3u8)
            }
            7 => {
                gal_mul(temp[4].clone(), 3u8)
                    ^ temp[5].clone()
                    ^ temp[6].clone()
                    ^ gal_mul(temp[7].clone(), 2u8)
            }

            // Third column transformation
            8 => {
                gal_mul(temp[8].clone(), 2u8)
                    ^ gal_mul(temp[9].clone(), 3u8)
                    ^ temp[10].clone()
                    ^ temp[11].clone()
            }
            9 => {
                temp[8].clone()
                    ^ gal_mul(temp[9].clone(), 2u8)
                    ^ gal_mul(temp[10].clone(), 3u8)
                    ^ temp[11].clone()
            }
            10 => {
                temp[8].clone()
                    ^ temp[9].clone()
                    ^ gal_mul(temp[10].clone(), 2u8)
                    ^ gal_mul(temp[11].clone(), 3u8)
            }
            11 => {
                gal_mul(temp[8].clone(), 3u8)
                    ^ temp[9].clone()
                    ^ temp[10].clone()
                    ^ gal_mul(temp[11].clone(), 2u8)
            }

            // Fourth column transformation
            12 => {
                gal_mul(temp[12].clone(), 2u8)
                    ^ gal_mul(temp[13].clone(), 3u8)
                    ^ temp[14].clone()
                    ^ temp[15].clone()
            }
            13 => {
                temp[12].clone()
                    ^ gal_mul(temp[13].clone(), 2u8)
                    ^ gal_mul(temp[14].clone(), 3u8)
                    ^ temp[15].clone()
            }
            14 => {
                temp[12].clone()
                    ^ temp[13].clone()
                    ^ gal_mul(temp[14].clone(), 2u8)
                    ^ gal_mul(temp[15].clone(), 3u8)
            }
            15 => {
                gal_mul(temp[12].clone(), 3u8)
                    ^ temp[13].clone()
                    ^ temp[14].clone()
                    ^ gal_mul(temp[15].clone(), 2u8)
            }

            _ => unreachable!(), // Ensure we never access an out-of-bounds index
        };
    });
}
