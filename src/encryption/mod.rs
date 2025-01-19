use tfhe::prelude::*;
use tfhe::{FheUint8, MatchValues};

use crate::log;

const SBOX: [u8; 3] = [2, 1, 0];

pub fn sub_bytes(state: &mut Vec<FheUint8>) {
    log!("Sub bytes started");
    let match_vector: Vec<(u8, u8)> = (0u8..=2u8).map(|x| (x, SBOX[x as usize])).collect();
    let match_values = MatchValues::new(match_vector).unwrap();

    for (index, i) in state.iter_mut().enumerate() {
        log!("{index}");
        (*i, _) = i.match_value(&match_values).unwrap();
    }
    log!("Sub bytes completed\n");
}

pub fn shift_rows(state: &mut Vec<FheUint8>) {
    log!("Shift rows started");

    let mut temp: Vec<FheUint8> = state.clone();

    // column 0
    state[0] = temp[0].clone();
    state[1] = temp[5].clone();
    state[2] = temp[10].clone();
    state[3] = temp[15].clone();

    // column 1
    state[4] = temp[4].clone();
    state[5] = temp[9].clone();
    state[6] = temp[14].clone();
    state[7] = temp[3].clone();

    // column 2
    state[8] = temp[8].clone();
    state[9] = temp[13].clone();
    state[10] = temp[2].clone();
    state[11] = temp[7].clone();

    // column 3
    state[12] = temp[12].clone();
    state[13] = temp[1].clone();
    state[14] = temp[6].clone();
    state[15] = temp[11].clone();

    log!("Shift rows completed\n");
}

pub fn gal_mul_org(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a;
    let mut b = b;

    const IRREDUCIBLE_POLY: u8 = 0x1b; // (x^8) + x^4 + x^3 + x + 1

    // Process each bit of the second operand
    while b != 0 {
        if (b & 1) != 0 {
            result ^= a;
        }

        // Shift a to the left, which corresponds to multiplying by x in GF(2^8)
        let high_bit_set = (a & 0x80) != 0;
        a <<= 1; // Multiply a by x

        // If the high bit was set before shifting, reduce a modulo the irreducible polynomial
        if high_bit_set {
            a ^= IRREDUCIBLE_POLY;
        }

        // Shift b to the right, moving to the next bit
        b >>= 1;
    }

    result
}
pub fn gal_mul_int(a: FheUint8, b: u8) -> FheUint8 {
    log!("Gal_mul_int started");
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
    log!("Gal_mul_int ended\n");
    result
}

pub fn gal_mul(a: FheUint8, b: FheUint8) -> FheUint8 {
    let mut result: FheUint8 = FheUint8::encrypt_trivial(0u8);
    let mut a = a.clone();
    let mut b = b.clone();

    // (x^8) + x^4 + x^3 + x + 1
    const IRREDUCIBLE_POLY: u8 = 0x1b;

    for _ in 0..8 {
        let res = result.clone() ^ a.clone();
        result = ((b.clone() & 1).ne(0)).if_then_else(&res, &result);
        let high_bit_set = (a.clone() & 0x80).ne(0);
        a <<= 1u8;
        a = (high_bit_set).if_then_else(&(a.clone() ^ IRREDUCIBLE_POLY), &a);
        b >>= 1u8;
    }

    result
}

// This will be used
pub fn mix_columns(state: &mut Vec<FheUint8>) {
    log!("Mix columns started");
    let temp = state.clone();

    // column 0
    state[0] = gal_mul_int(temp[0].clone(), 2u8)
        ^ gal_mul_int(temp[1].clone(), 3u8)
        ^ temp[2].clone()
        ^ temp[3].clone();

    state[1] = temp[0].clone()
        ^ gal_mul_int(temp[1].clone(), 2u8)
        ^ gal_mul_int(temp[2].clone(), 3u8)
        ^ temp[3].clone();

    state[2] = temp[0].clone()
        ^ temp[1].clone()
        ^ gal_mul_int(temp[2].clone(), 2u8)
        ^ gal_mul_int(temp[3].clone(), 3u8);

    state[3] = gal_mul_int(temp[0].clone(), 3u8)
        ^ temp[1].clone()
        ^ temp[2].clone()
        ^ gal_mul_int(temp[3].clone(), 2u8);

    // column 1
    state[4] = gal_mul_int(temp[4].clone(), 2u8)
        ^ gal_mul_int(temp[5].clone(), 3u8)
        ^ temp[6].clone()
        ^ temp[7].clone();

    state[5] = temp[4].clone()
        ^ gal_mul_int(temp[5].clone(), 2u8)
        ^ gal_mul_int(temp[6].clone(), 3u8)
        ^ temp[7].clone();

    state[6] = temp[4].clone()
        ^ temp[5].clone()
        ^ gal_mul_int(temp[6].clone(), 2u8)
        ^ gal_mul_int(temp[7].clone(), 3u8);

    state[7] = gal_mul_int(temp[4].clone(), 3u8)
        ^ temp[5].clone()
        ^ temp[6].clone()
        ^ gal_mul_int(temp[7].clone(), 2u8);

    // column 2
    state[8] = gal_mul_int(temp[8].clone(), 2u8)
        ^ gal_mul_int(temp[9].clone(), 3u8)
        ^ temp[10].clone()
        ^ temp[11].clone();

    state[9] = temp[8].clone()
        ^ gal_mul_int(temp[9].clone(), 2u8)
        ^ gal_mul_int(temp[10].clone(), 3u8)
        ^ temp[11].clone();

    state[10] = temp[8].clone()
        ^ temp[9].clone()
        ^ gal_mul_int(temp[10].clone(), 2u8)
        ^ gal_mul_int(temp[11].clone(), 3u8);

    state[11] = gal_mul_int(temp[8].clone(), 3u8)
        ^ temp[9].clone()
        ^ temp[10].clone()
        ^ gal_mul_int(temp[11].clone(), 2u8);

    // column 3
    state[12] = gal_mul_int(temp[12].clone(), 2u8)
        ^ gal_mul_int(temp[13].clone(), 3u8)
        ^ temp[14].clone()
        ^ temp[15].clone();

    state[13] = temp[12].clone()
        ^ gal_mul_int(temp[13].clone(), 2u8)
        ^ gal_mul_int(temp[14].clone(), 3u8)
        ^ temp[15].clone();

    state[14] = temp[12].clone()
        ^ temp[13].clone()
        ^ gal_mul_int(temp[14].clone(), 2u8)
        ^ gal_mul_int(temp[15].clone(), 3u8);

    state[15] = gal_mul_int(temp[12].clone(), 3u8)
        ^ temp[13].clone()
        ^ temp[14].clone()
        ^ gal_mul_int(temp[15].clone(), 2u8);

    log!("Mix columns completed\n");
}

fn mix_columns_org(state: &mut [u8; 16]) {
    let temp = *state;

    // column 0
    state[0] = gal_mul_org(temp[0], 0x02) ^ gal_mul_org(temp[1], 0x03) ^ temp[2] ^ temp[3];
    state[1] = temp[0] ^ gal_mul_org(temp[1], 0x02) ^ gal_mul_org(temp[2], 0x03) ^ temp[3];
    state[2] = temp[0] ^ temp[1] ^ gal_mul_org(temp[2], 0x02) ^ gal_mul_org(temp[3], 0x03);
    state[3] = gal_mul_org(temp[0], 0x03) ^ temp[1] ^ temp[2] ^ gal_mul_org(temp[3], 0x02);

    // column 1
    state[4] = gal_mul_org(temp[4], 0x02) ^ gal_mul_org(temp[5], 0x03) ^ temp[6] ^ temp[7];
    state[5] = temp[4] ^ gal_mul_org(temp[5], 0x02) ^ gal_mul_org(temp[6], 0x03) ^ temp[7];
    state[6] = temp[4] ^ temp[5] ^ gal_mul_org(temp[6], 0x02) ^ gal_mul_org(temp[7], 0x03);
    state[7] = gal_mul_org(temp[4], 0x03) ^ temp[5] ^ temp[6] ^ gal_mul_org(temp[7], 0x02);

    // column 2
    state[8] = gal_mul_org(temp[8], 0x02) ^ gal_mul_org(temp[9], 0x03) ^ temp[10] ^ temp[11];
    state[9] = temp[8] ^ gal_mul_org(temp[9], 0x02) ^ gal_mul_org(temp[10], 0x03) ^ temp[11];
    state[10] = temp[8] ^ temp[9] ^ gal_mul_org(temp[10], 0x02) ^ gal_mul_org(temp[11], 0x03);
    state[11] = gal_mul_org(temp[8], 0x03) ^ temp[9] ^ temp[10] ^ gal_mul_org(temp[11], 0x02);

    // column 3
    state[12] = gal_mul_org(temp[12], 0x02) ^ gal_mul_org(temp[13], 0x03) ^ temp[14] ^ temp[15];
    state[13] = temp[12] ^ gal_mul_org(temp[13], 0x02) ^ gal_mul_org(temp[14], 0x03) ^ temp[15];
    state[14] = temp[12] ^ temp[13] ^ gal_mul_org(temp[14], 0x02) ^ gal_mul_org(temp[15], 0x03);
    state[15] = gal_mul_org(temp[12], 0x03) ^ temp[13] ^ temp[14] ^ gal_mul_org(temp[15], 0x02);
}
