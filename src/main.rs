// #![allow(unused)]
mod decryption;
// #[macro_export]
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

// const SBOX: [u8; 4] = [0, 1, 2, 3];

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

fn get_match_values() -> MatchValues<u8> {
    let match_vector = (0u8..=255u8).map(|x| (x, SBOX[x as usize])).collect();

    MatchValues::new(match_vector).unwrap()
}

fn aes_encrypt_block(input: &Vec<FheUint8>, output: &mut [FheUint8; 16], key: &[FheUint8; 16]) {
    let mut state = input.clone();
    let mut expanded_key: [FheUint<FheUint8Id>; 176] =
        std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

    key_expansion_fhe(key, &mut expanded_key);

    add_blocks(&mut state, &expanded_key[0..16]);

    for round in 1..10 {
        sub_bytes(&mut state);

        shift_rows(&mut state);

        mix_columns(&mut state);

        // Add round key
        add_blocks(&mut state, &expanded_key[round * 16..(round + 1) * 16]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_blocks(&mut state, &expanded_key[160..176]);

    output.clone_from_slice(&state);
}

fn increment_counter(iv: &[u8; 16]) -> [u8; 16] {
    let mut counter = iv.clone();

    let len = counter.len();
    for i in (0..len).rev() {
        if counter[i] == 0xFF {
            // If the byte is 0xFF, set it to 0x00 and carry over to the next byte
            counter[i] = 0x00;
        } else {
            // Increment the byte and stop
            counter[i] += 1;
            break;
        }
    }

    return counter;
}

fn aes_decrypt_block(input: &Vec<FheUint8>, output: &mut [FheUint8; 16], key: &[FheUint8; 16]) {
    let mut state = input.clone();
    let mut expanded_key: [FheUint<FheUint8Id>; 176] =
        std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

    key_expansion_fhe(key, &mut expanded_key);

    add_blocks(&mut state, &expanded_key[160..176]);

    for round in (1..10).rev() {
        inv_shift_rows(&mut state);

        inv_sub_bytes(&mut state);

        add_blocks(&mut state, &expanded_key[round * 16..(round + 1) * 16]);

        inv_mix_columns(&mut state);

        // Add round key
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_blocks(&mut state, &expanded_key[0..16]);

    output.clone_from_slice(&state);
}

fn hex_to_u8_array(hex: &str) -> Result<[u8; 16], &'static str> {
    if hex.len() != 32 {
        return Err("Hex string must be 32 characters long for 128 bits");
    }

    let mut array = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8 in hex string")?;
        array[i] = u8::from_str_radix(hex_str, 16).map_err(|_| "Invalid hex character")?;
    }

    Ok(array)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 1)]
    number_of_outputs: u32,

    #[arg(short, long)]
    iv: String,

    #[arg(short, long)]
    key: String,
}

fn main() {
    // let iv = hex_to_u8_array("00112233445566778899aabbccddeeff").unwrap();
    // let expected_state = hex_to_u8_array("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
    // let key = hex_to_u8_array("000102030405060708090a0b0c0d0e0f").unwrap();

    let encryption_start = Instant::now();

    let args = Args::parse();
    println!("{}, {}, {}", args.iv, args.key, args.number_of_outputs);

    let iv = hex_to_u8_array(&args.iv).unwrap();
    let key = hex_to_u8_array(&args.key).unwrap();

    let mut expected_state = iv.clone();
    let aes_cipher = Aes128::new((&key).into());
    aes_cipher.encrypt_block((&mut expected_state).into());

    log!("AES128 started");

    let mut counters_encryption: Vec<[u8; 16]> = vec![iv];

    for _ in 0..(args.number_of_outputs - 1) {
        let incremented_iv = increment_counter(&iv);
        counters_encryption.push(incremented_iv);
    }

    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    let key_fhe: [FheUint<FheUint8Id>; 16] =
        std::array::from_fn(|index| FheUint8::encrypt_trivial(key[index]));

    let mut output_encryption: [FheUint<FheUint8Id>; 16] =
        std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

    println!("Executing AES-CTR mode");

    for i in 0..(args.number_of_outputs) as usize {
        let mut _output_encryption: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

        let input: Vec<FheUint8> = counters_encryption[i]
            .iter()
            .map(|x| FheUint8::encrypt_trivial(*x))
            .collect();

        if i == 0 {
            aes_encrypt_block(&input, &mut output_encryption, &key_fhe);
            continue;
        }

        aes_encrypt_block(&input, &mut _output_encryption, &key_fhe);
    }

    let encryption_duration = encryption_start.elapsed().as_secs();

    for i in 0..16 {
        let result: u8 = output_encryption[i].decrypt(&cks);
        log!("{:?} and {}", result, expected_state[i]);
    }

    log!("AES encryption completed");

    println!(
        "AES encryption of {} outputs took {} seconds",
        args.number_of_outputs, encryption_duration
    );
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write, time::Instant};

    use super::*;

    #[test]
    fn aes_encryption() {
        let encryption_start = Instant::now();

        let iv = hex_to_u8_array("00112233445566778899aabbccddeeff").unwrap();
        let key = hex_to_u8_array("000102030405060708090a0b0c0d0e0f").unwrap();

        let mut expected_state = iv.clone();
        let aes_cipher = Aes128::new((&key).into());
        aes_cipher.encrypt_block((&mut expected_state).into());

        let number_of_outputs = 1;

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
            std::array::from_fn(|index| FheUint8::encrypt_trivial(key[index]));

        let mut output_encryption: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

        for i in 0..number_of_outputs {
            let mut _output_encryption: [FheUint<FheUint8Id>; 16] =
                std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

            let input: Vec<FheUint8> = counters_encryption[i]
                .iter()
                .map(|x| FheUint8::encrypt_trivial(*x))
                .collect();

            if i == 0 {
                aes_encrypt_block(&input, &mut output_encryption, &key_fhe);
                continue;
            }

            aes_encrypt_block(&input, &mut _output_encryption, &key_fhe);
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

        // Write the output_encryption to an output.txt file

        let mut file = File::create("output.txt").expect("Unable to create file");
        for i in 0..16 {
            let result: u8 = output_encryption[i].decrypt(&cks);
            writeln!(file, "{:02x}", result).expect("Unable to write data");
        }
    }

    #[test]
    fn aes_decryption() {
        let decryption_start = Instant::now();

        let iv = hex_to_u8_array("00112233445566778899aabbccddeeff").unwrap();
        let expected_state = hex_to_u8_array("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let key = hex_to_u8_array("000102030405060708090a0b0c0d0e0f").unwrap();
        let number_of_outputs = 3;

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
            std::array::from_fn(|index| FheUint8::encrypt_trivial(key[index]));

        let mut output_decryption: [FheUint<FheUint8Id>; 16] =
            std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

        for i in 0..number_of_outputs {
            let mut _output_decryption: [FheUint<FheUint8Id>; 16] =
                std::array::from_fn(|_| FheUint8::encrypt_trivial(0u8));

            let input: Vec<FheUint8> = counters_decryption[i]
                .iter()
                .map(|x| FheUint8::encrypt_trivial(*x))
                .collect();

            if i == 0 {
                aes_decrypt_block(&input, &mut output_decryption, &key_fhe);
                continue;
            }

            aes_decrypt_block(&input, &mut _output_decryption, &key_fhe);
        }

        let decryption_duration = decryption_start.elapsed().as_secs();

        for i in 0..16 {
            let result: u8 = output_decryption[i].decrypt(&cks);
            log!("{:?} and {}", result, iv[i]);
        }

        println!(
            "AES decryption of {} outputs took {} seconds",
            number_of_outputs, decryption_duration
        );
    }
}
