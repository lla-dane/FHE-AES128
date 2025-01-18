use tfhe::{ConfigBuilder, generate_keys, set_server_key, CpuFheUint8Array, ClearArray,MatchValues,FheUint8};
use tfhe::prelude::*;



const SBOX: [u8; 3] = [
    2,1,0
]; 



pub fn sub_bytes( state: &mut Vec<FheUint8>) {
    let match_vector: Vec<(u8, u8)> = (0u8..=2u8).map(|x| (x, SBOX[x as usize])).collect();
    println!("{:?}", match_vector);
    let match_values = MatchValues::new(match_vector).unwrap();
    // (state[0],_)=state[0].match_value(&match_values).unwrap();
    for i in state.iter_mut() {
        // println!("{:?}", i);
        (*i,_)= i.match_value(&match_values).unwrap();
    }
    
}

pub fn shift_rows(state: &mut Vec<FheUint8>) {
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
    
}
pub fn gal_mul_org (a: u8, b: u8) -> u8 {
    let mut result: u8 = 0; // Result of the multiplication
    let mut a = a; // Copy of the first operand
    let mut b = b; // Copy of the second operand

    // Irreducible polynomial for GF(2^8)
    const IRREDUCIBLE_POLY: u8 = 0x1b; // (x^8) + x^4 + x^3 + x + 1

    // Process each bit of the second operand
    while b != 0 {
        // If the least significant bit of b is 1, add the current a to the result
        if (b & 1) != 0 {
            result ^= a; // XOR is used instead of addition in GF(2^8)
        }

        // Shift a to the left, which corresponds to multiplying by x in GF(2^8)
        let high_bit_set = (a & 0x80) != 0; // Check if the high bit (x^7) is set
        a <<= 1; // Multiply a by x

        // If the high bit was set before shifting, reduce a modulo the irreducible polynomial
        if high_bit_set {
            a ^= IRREDUCIBLE_POLY; // Perform the reduction
        }

        // Shift b to the right, moving to the next bit
        b >>= 1;
    }

    result
}
pub fn gal_mul (a: FheUint8, b: FheUint8) -> FheUint8 {
    let mut result: FheUint8 = FheUint8::encrypt_trivial(0u8); // Result of the multiplication
    let mut a = a.clone(); // Copy of the first operand
    let mut b = b.clone(); // Copy of the second operand
    // Irreducible polynomial for GF(2^8)
    const IRREDUCIBLE_POLY: u8 = 0x1b; // (x^8) + x^4 + x^3 + x + 1

    // // Process each bit of the second operand

    for _ in 0..8{
        let res=result.clone()^a.clone();
        result=((b.clone() & 1).ne(0) ).if_then_else(&res, &result);
        let high_bit_set = (a.clone() & 0x80).ne(0);
        a<<=1u8; 
        a=(high_bit_set).if_then_else(&(a.clone()^IRREDUCIBLE_POLY), &a);
        b>>=1u8;
    }

    result
}
fn mix_columns(state: &mut Vec<FheUint8>) {
    let temp = state.clone();

    // column 0
    state[0] = gal_mul(temp[0].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[1].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[2].clone() ^ temp[3].clone();
    state[1] = temp[0].clone() ^ gal_mul(temp[1].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[2].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[3].clone();
    state[2] = temp[0].clone() ^ temp[1].clone() ^ gal_mul(temp[2].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[3].clone(), FheUint8::encrypt_trivial(3u8));
    state[3] = gal_mul(temp[0].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[1].clone() ^ temp[2].clone() ^ gal_mul(temp[3].clone(), FheUint8::encrypt_trivial(2u8));

    // column 1
    state[4] = gal_mul(temp[4].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[5].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[6].clone() ^ temp[7].clone();
    state[5] = temp[4].clone() ^ gal_mul(temp[5].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[6].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[7].clone();
    state[6] = temp[4].clone() ^ temp[5].clone() ^ gal_mul(temp[6].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[7].clone(), FheUint8::encrypt_trivial(3u8));
    state[7] = gal_mul(temp[4].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[5].clone() ^ temp[6].clone() ^ gal_mul(temp[7].clone(), FheUint8::encrypt_trivial(2u8));

    // column 2
    state[8] = gal_mul(temp[8].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[9].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[10].clone() ^ temp[11].clone();
    state[9] = temp[8].clone() ^ gal_mul(temp[9].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[10].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[11].clone();
    state[10] = temp[8].clone() ^ temp[9].clone() ^ gal_mul(temp[10].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[11].clone(), FheUint8::encrypt_trivial(3u8));
    state[11] = gal_mul(temp[8].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[9].clone() ^ temp[10].clone() ^ gal_mul(temp[11].clone(), FheUint8::encrypt_trivial(2u8));

    // column 3
    state[12] = gal_mul(temp[12].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[13].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[14].clone() ^ temp[15].clone();
    state[13] = temp[12].clone() ^ gal_mul(temp[13].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[14].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[15].clone();
    state[14] = temp[12].clone() ^ temp[13].clone() ^ gal_mul(temp[14].clone(), FheUint8::encrypt_trivial(2u8)) ^ gal_mul(temp[15].clone(), FheUint8::encrypt_trivial(3u8));
    state[15] = gal_mul(temp[12].clone(), FheUint8::encrypt_trivial(3u8)) ^ temp[13].clone() ^ temp[14].clone() ^ gal_mul(temp[15].clone(), FheUint8::encrypt_trivial(2u8));
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
