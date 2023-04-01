use rand::RngCore;
//use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use std::fs::File;
use std::io::prelude::*;


mod hkdf;

fn main() {
    let mut salt = [0u8; 64];
    let mut rand = ChaCha20Rng::from_entropy();
    rand::thread_rng().fill_bytes(&mut salt);



    println!("Hello, world!{:?}", salt);
}
