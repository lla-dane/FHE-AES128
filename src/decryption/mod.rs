use crate::log;
use rayon::prelude::*;
use std::thread;
use std::time::Duration;
use tfhe::prelude::*;
use tfhe::{FheUint8, MatchValues};

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub fn inv_sub_bytes(state: &mut Vec<FheUint8>) {
    let match_vector: Vec<(u8, u8)> = (0u8..=255u8).map(|x| (x, INV_SBOX[x as usize])).collect();
    let match_values = MatchValues::new(match_vector).unwrap();

    state
        .par_iter_mut() // Parallel iterator for mutable access to state
        .enumerate() // Add index for logging
        .for_each(|(index, i)| {
            (*i, _) = i.match_value(&match_values).unwrap();
        });
}

pub fn inv_shift_rows(state: &mut Vec<FheUint8>) {
    let temp: Vec<FheUint8> = state.clone();

    // Process each element independently in parallel
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
