use tfhe::{ConfigBuilder, generate_keys, set_server_key, CpuFheUint8Array, ClearArray,MatchValues,FheUint8};
use tfhe::prelude::*;



const SBOX: [u8; 3] = [
    2,1,0
]; 



fn sub_bytes( state: &mut Vec<FheUint8>) {
    let match_vector: Vec<(u8, u8)> = (0u8..=2u8).map(|x| (x, SBOX[x as usize])).collect();
    println!("{:?}", match_vector);
    let match_values = MatchValues::new(match_vector).unwrap();
    // (state[0],_)=state[0].match_value(&match_values).unwrap();
    for i in state.iter_mut() {
        // println!("{:?}", i);
        (*i,_)= i.match_value(&match_values).unwrap();
    }
    
}

fn shift_rows(state: &mut Vec<FheUint8>) {
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

fn gal_mul (a: FheUint8, b: FheUint8) -> FheUint8 {
    let mut result: FheUint8 = FheUint8::encrypt_trivial(0u8); // Result of the multiplication
    let mut a = a; // Copy of the first operand
    let mut b = b; // Copy of the second operand

    // Irreducible polynomial for GF(2^8)
    const IRREDUCIBLE_POLY: u8 = 0x1b; // (x^8) + x^4 + x^3 + x + 1

    // // Process each bit of the second operand
    let res=result.clone()^a;
    result=((b & 1).ne(0) ).if_then_else(&res, &result);
    // while b != 0 {
    //     // If the least significant bit of b is 1, add the current a to the result
    //     if ((b & 1) != 0).if_then_else(result^=a, _) 
        

    //     // Shift a to the left, which corresponds to multiplying by x in GF(2^8)
    //     let high_bit_set = (a & 0x80) != 0; // Check if the high bit (x^7) is set
    //     a <<= 1; // Multiply a by x

    //     // If the high bit was set before shifting, reduce a modulo the irreducible polynomial
    //     if high_bit_set {
    //         a ^= IRREDUCIBLE_POLY; // Perform the reduction
    //     }

    //     // Shift b to the right, moving to the next bit
    //     b >>= 1;
    // }

    result
}

fn main() {
    
    let key: [u8; 3] = [
        1,2,0
    ];
    let mut iv: [u8; 16] = [
        0xd4, 0xe0, 0xb8, 0x1e,
        0x27, 0xbf, 0xb4, 0x41,
        0x11, 0x98, 0x5d, 0x52,
        0xae, 0xf1, 0xe5, 0x30,
    ];
    let expected_state: [u8; 16] = [
        0xd4, 0xbf, 0x5d, 0x30,
        0x27, 0x98, 0xe5, 0x1e,
        0x11, 0xf1, 0xb8, 0x41,
        0xae, 0xe0, 0xb4, 0x52,
    ];
    println!("{:?}", expected_state);
    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);
    let mut xs:Vec<FheUint8> = vec![];
    for i in iv.iter() {
        // println!("{:?}", i);
        let x = FheUint8::encrypt(*i, &cks);
        xs.push(x);
    }
    // sub_bytes(&mut xs);

    // shift_rows(&mut xs);

    gal_mul(xs[0].clone(), xs[1].clone());
    let mut output:Vec<u8> = vec![];
    for i in xs.iter() {
        let z:u8=i.decrypt(&cks);
        output.push(z);
    }

    println!("{:?}", output);
//     println!("{:?}", xs.shape());
// ;

//     for i in xs.into_container() {
//         let x = i.clone();
//         let (result, matched): (FheUint8, _) = x.match_value(&match_values)
//         .unwrap();
//         let matched = matched.decrypt(&cks);
//         println!("{:?}", matched);

//     }
    // let (result, matched): (FheUint8, _) = xss.match_value(&match_values)
    //     .unwrap(); // All possible output values fit in a u8
    // let matched = matched.decrypt(&cks);
    // println!("Matched: {}", matched);
    // let result:Vec<u8> = xss.decrypt(&cks);
    // for i in 0..4 {
    // }


    println!("Hello, world!");
}
