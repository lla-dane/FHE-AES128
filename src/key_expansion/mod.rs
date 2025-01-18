use crate::{SBOX, get_match_values};
use tfhe::{prelude::FheTrivialEncrypt, FheUint, FheUint8, FheUint8Id};

const R_CONSTANTS: [u8; 11] = [
    0,1,2,3,0,1,2,3,0,1,2
];

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

fn key_expansion_fhe(key: &[FheUint8; 16], expanded_key: &mut [FheUint8; 176]) {
    expanded_key[0..16].clone_from_slice(&key[..]);
    let mut i = 16usize;
    let mut temp: [FheUint<FheUint8Id>; 4] = [
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
        FheUint8::encrypt_trivial(0u8),
    ];

    let match_values = get_match_values();

    while i < 34 {
        temp.clone_from_slice(&expanded_key[i - 4..i]);

        if i % 16 == 0 {
            // rotate left
            temp.rotate_left(1);
            for j in 0..4 {
                let (result, _): (FheUint8, _) = temp[j].match_value(&match_values).unwrap();
                temp[j] = result;
            }

            // XOR with round constant
            temp[0] ^= R_CONSTANTS[i / 16];
        }

        for j in 0..4 {
            expanded_key[i] = expanded_key[i - 16].clone() ^ temp[j].clone();
            i += 1;
        }
        println!("i:{}",i);
    }
}

#[cfg(test)]
mod tests {
    use tfhe::{
        ConfigBuilder, generate_keys,
        prelude::{FheDecrypt, FheEncrypt},
        set_server_key,
    };

    use super::*;

    #[test]
    fn test_key_generation() {
        let key: [u8; 16] = [1, 2, 0, 1, 0, 2, 0, 2, 1, 1, 0, 2, 1, 0, 2, 2];

        let mut expanded_key = [0u8; 176];
        key_expansion(&key, &mut expanded_key);
        println!("{:?}", expanded_key);
    }

    #[test]
    fn test_key_expansion_fhe() {
        println!("function started");
        let (client_key, server_key) = generate_keys(ConfigBuilder::default().build());
        set_server_key(server_key);
        println!("serverkey");

        let key: [u8; 16] = [1, 2, 0, 1, 0, 2, 0, 2, 1, 1, 0, 2, 1, 0, 2, 2];

        let encrypted_key: [FheUint8; 16] = key.map(|x| FheUint8::encrypt(x, &client_key));
        let mut expanded_key: [FheUint<FheUint8Id>; 176] =
            std::array::from_fn(|_| FheUint8::encrypt(0u8, &client_key));

        key_expansion_fhe(&encrypted_key, &mut expanded_key);

        let decrypted: [u8; 176] = expanded_key.map(|x| x.decrypt(&client_key));
        println!("{:?}", decrypted);
    }
}
