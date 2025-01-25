#[macro_use]
use crate::log;
use crate::{get_match_values, SBOX};
use tfhe::{prelude::FheTrivialEncrypt, FheUint, FheUint8, FheUint8Id};
use rayon::prelude::*;

const R_CONSTANTS: [u8; 11] =[0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

// Expands the key into multiple round keys.
// Nk = 4 as key = 128
// 10 passes * 16 bytes + 16 bytes = 176
fn key_expansion(key: &[u8; 16], expanded_key: &mut [u8; 176]) {
    // first 16 bits are the original key
    expanded_key[0..16].copy_from_slice(key);

    let mut i = 16;
    let mut temp = [0u8; 4];

    while i < 176 {
        temp.copy_from_slice(&expanded_key[i - 4..i]);

        if i % 16 == 0 {
            // Rotate left
            temp.rotate_left(1);
            // Substitute bytes using S-box
            for j in 0..4 {
                temp[j] = SBOX[temp[j] as usize];
            }
            // XOR with round constant
            temp[0] ^= R_CONSTANTS[i / 16];
        }

        for j in 0..4 {
            expanded_key[i] = expanded_key[i - 16] ^ temp[j];
            i += 1;
        }
    }
}

pub fn key_expansion_fhe(key: &[FheUint8; 16], expanded_key: &mut [FheUint8; 176]) {
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
        log!("i: {}", i);
    }
}

#[cfg(test)]
mod tests {
    use tfhe::{
        generate_keys,
        prelude::{FheDecrypt, FheEncrypt},
        set_server_key, ConfigBuilder,
    };

    use super::*;

    #[test]
    fn test_key_generation() {
        let key: [u8; 16] = [1, 2, 0, 1, 0, 2, 0, 2, 1, 1, 0, 2, 1, 0, 2, 2];

        let mut expanded_key = [0u8; 176];
        key_expansion(&key, &mut expanded_key);
        log!("{:?}", expanded_key);
    }

    #[test]
    fn key_fhe() {
        log!("function started");
        let (client_key, server_key) = generate_keys(ConfigBuilder::default().build());
        set_server_key(server_key);
        log!("serverkey");

        let key: [u8; 16] = [1, 2, 0, 1, 0, 2, 0, 2, 1, 1, 0, 2, 1, 0, 2, 2];

        let encrypted_key: [FheUint8; 16] = key.map(|x| FheUint8::encrypt(x, &client_key));
        let mut expanded_key: [FheUint<FheUint8Id>; 176] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &client_key));

        key_expansion_fhe(&encrypted_key, &mut expanded_key);

        let decrypted: [u8; 176] = expanded_key.map(|x| x.decrypt(&client_key));
        log!("{:?}", decrypted);
    }
}
