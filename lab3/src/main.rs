use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, 
    generic_array::{GenericArray, typenum::U16},
};
use urandom;

fn randbytes(n: usize) -> Vec<u8>{
    let mut rng = urandom::new();
    let mut res = Vec::new();
    for _ in 0..n{
        res.push(rng.next::<u8>());
    }
    res
}

fn aes_block_encrypt(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8>{
    if data.len() != 16{
        panic!("Incorrect block length");
    }
    if key.len() != 16{
        panic!("Incorrect key length");
    }

    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let mut data = GenericArray::<u8, U16>::clone_from_slice(data);
    
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut data);
    Vec::from(&data[..])
}


fn main(){
    let data = randbytes(16);
    let key = randbytes(16);
    let cipher;
    println!("Hello, world!");
}
