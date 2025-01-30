use crate::log;
use rayon::prelude::*;
use std::thread;
use std::time::Duration;
use tfhe::prelude::*;
use tfhe::{FheUint8, MatchValues};

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

pub fn add_blocks(state: &mut Vec<FheUint8>, b: &[FheUint8]) {
    state
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, state_elem)| {
            *state_elem ^= b[i].clone();
        });
}

pub fn sub_bytes(state: &mut Vec<FheUint8>) {
    let match_vector: Vec<(u8, u8)> = (0u8..=255u8).map(|x| (x, SBOX[x as usize])).collect();
    let match_values = MatchValues::new(match_vector).unwrap();

    state
        .par_iter_mut() // Parallel iterator for mutable access to state
        .enumerate() // Add index for logging
        .for_each(|(index, i)| {
            (*i, _) = i.match_value(&match_values).unwrap();
        });
}
pub fn shift_rows(state: &mut Vec<FheUint8>) {
    let temp: Vec<FheUint8> = state.clone();

    // Process each element independently in parallel
    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = match i {
            0 => temp[0].clone(),
            1 => temp[5].clone(),
            2 => temp[10].clone(),
            3 => temp[15].clone(),
            4 => temp[4].clone(),
            5 => temp[9].clone(),
            6 => temp[14].clone(),
            7 => temp[3].clone(),
            8 => temp[8].clone(),
            9 => temp[13].clone(),
            10 => temp[2].clone(),
            11 => temp[7].clone(),
            12 => temp[12].clone(),
            13 => temp[1].clone(),
            14 => temp[6].clone(),
            15 => temp[11].clone(),
            _ => unreachable!(),
        };
    });
}

pub fn gal_mul_int(a: FheUint8, b: u8) -> FheUint8 {
    let mut result: FheUint8 = FheUint8::encrypt_trivial(0u8); // Result of the multiplication
    let mut a = a;
    let mut b = b;

    // (x^8) + x^4 + x^3 + x + 1
    const IRREDUCIBLE_POLY: u8 = 0x1b;

    // Process each bit of the second operand
    while b != 0 {
        // If the least significant bit of b is 1, add the current a to the result
        if (b & 1) != 0 {
            result ^= a.clone(); // XOR is used instead of addition in GF(2^8)
        }

        // Shift a to the left, which corresponds to multiplying by x in GF(2^8)
        let high_bit_set = (a.clone() & 0x80).ne(0); // Check if the high bit (x^7) is set
        a <<= 1u8; // Multiply a by x

        // If the high bit was set before shifting, reduce a modulo the irreducible polynomial
        a = (high_bit_set).if_then_else(&(a.clone() ^ IRREDUCIBLE_POLY), &a);

        // Shift b to the right, moving to the next bit
        b >>= 1;
    }
    result
}

pub fn mix_columns(state: &mut Vec<FheUint8>) {
    let temp = state.clone();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = match i {
            0 => {
                gal_mul_int(temp[0].clone(), 2u8)
                    ^ gal_mul_int(temp[1].clone(), 3u8)
                    ^ temp[2].clone()
                    ^ temp[3].clone()
            }
            1 => {
                temp[0].clone()
                    ^ gal_mul_int(temp[1].clone(), 2u8)
                    ^ gal_mul_int(temp[2].clone(), 3u8)
                    ^ temp[3].clone()
            }
            2 => {
                temp[0].clone()
                    ^ temp[1].clone()
                    ^ gal_mul_int(temp[2].clone(), 2u8)
                    ^ gal_mul_int(temp[3].clone(), 3u8)
            }
            3 => {
                gal_mul_int(temp[0].clone(), 3u8)
                    ^ temp[1].clone()
                    ^ temp[2].clone()
                    ^ gal_mul_int(temp[3].clone(), 2u8)
            }

            4 => {
                gal_mul_int(temp[4].clone(), 2u8)
                    ^ gal_mul_int(temp[5].clone(), 3u8)
                    ^ temp[6].clone()
                    ^ temp[7].clone()
            }
            5 => {
                temp[4].clone()
                    ^ gal_mul_int(temp[5].clone(), 2u8)
                    ^ gal_mul_int(temp[6].clone(), 3u8)
                    ^ temp[7].clone()
            }
            6 => {
                temp[4].clone()
                    ^ temp[5].clone()
                    ^ gal_mul_int(temp[6].clone(), 2u8)
                    ^ gal_mul_int(temp[7].clone(), 3u8)
            }
            7 => {
                gal_mul_int(temp[4].clone(), 3u8)
                    ^ temp[5].clone()
                    ^ temp[6].clone()
                    ^ gal_mul_int(temp[7].clone(), 2u8)
            }

            8 => {
                gal_mul_int(temp[8].clone(), 2u8)
                    ^ gal_mul_int(temp[9].clone(), 3u8)
                    ^ temp[10].clone()
                    ^ temp[11].clone()
            }
            9 => {
                temp[8].clone()
                    ^ gal_mul_int(temp[9].clone(), 2u8)
                    ^ gal_mul_int(temp[10].clone(), 3u8)
                    ^ temp[11].clone()
            }
            10 => {
                temp[8].clone()
                    ^ temp[9].clone()
                    ^ gal_mul_int(temp[10].clone(), 2u8)
                    ^ gal_mul_int(temp[11].clone(), 3u8)
            }
            11 => {
                gal_mul_int(temp[8].clone(), 3u8)
                    ^ temp[9].clone()
                    ^ temp[10].clone()
                    ^ gal_mul_int(temp[11].clone(), 2u8)
            }

            12 => {
                gal_mul_int(temp[12].clone(), 2u8)
                    ^ gal_mul_int(temp[13].clone(), 3u8)
                    ^ temp[14].clone()
                    ^ temp[15].clone()
            }
            13 => {
                temp[12].clone()
                    ^ gal_mul_int(temp[13].clone(), 2u8)
                    ^ gal_mul_int(temp[14].clone(), 3u8)
                    ^ temp[15].clone()
            }
            14 => {
                temp[12].clone()
                    ^ temp[13].clone()
                    ^ gal_mul_int(temp[14].clone(), 2u8)
                    ^ gal_mul_int(temp[15].clone(), 3u8)
            }
            15 => {
                gal_mul_int(temp[12].clone(), 3u8)
                    ^ temp[13].clone()
                    ^ temp[14].clone()
                    ^ gal_mul_int(temp[15].clone(), 2u8)
            }
            _ => unreachable!(),
        };
    });
}
