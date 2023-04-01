use rand::RngCore;
//use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use std::fs;
use std::fs::File;

use std::io::prelude::*;
use serde_json::Result;
use serde_json::json;

mod lib;

use crate::lib::{HkdfExtract, HkdfExpand, PBKDF2};

fn mix(a: &Vec<f64>, b: &Vec<f64>) -> Vec<u8>{
    let mut res: Vec<u8> = vec![];    
    for i in 0..a.len(){
        let u = ((a[i] / 400.0 + 3.0 * b[i]) * (256.0 / 3.5)).round() as u8;
        res.push(u);
    }
    res
}

fn hkdf_test(){
    let mut fc1 = fs::read_to_string("data/ozone.json").expect("Something wrong with json");
    let mut fc2 = fs::read_to_string("data/cloudcover.json").expect("Something wrong with json");
    let data1: Vec<f64> = serde_json::from_str(&fc1).expect("Failed to unpack json");
    let data2: Vec<f64> = serde_json::from_str(&fc2).expect("Failed to unpack json");

    let data = mix(&data1, &data2);

    let mut salt = vec![0u8; 256];
    let mut rand = ChaCha20Rng::from_entropy();
    rand::thread_rng().fill_bytes(&mut salt);

    let OKM = HkdfExtract(&salt, &data);

    let mut keys: Vec<Vec<u8>> = vec![vec![]];
    for i in 1..1001{
        keys.push(HkdfExpand(&OKM, &keys[i-1], &b"Alex".to_vec(), i as u32));
    }

    let mut bits = Vec::<u16>::new();

    for i in 1..1001{
        let mut m: u16 = (keys[i][1] >> 6) as u16;
        m += (keys[i][0] << 2) as u16;
        bits.push(m);
    }
    let j_bits = json!(bits);

    let mut file = File::create("data/res.json").unwrap();
    file.write_all(j_bits.to_string().as_bytes()).unwrap();
}

fn pbkdf2_test(){
    let mut fc = fs::read_to_string("data/passwords.json").expect("Something wrong with json");
    let jpas: Vec<&str> = serde_json::from_str(&fc).expect("Failed to unpack json");

    let mut passes = Vec::<Vec<u8>>::new();
    for p in jpas{
        passes.push(Vec::from(p));
    }

    let mut salt = vec![0u8; 256];
    let mut rand = ChaCha20Rng::from_entropy();
    
    let mut keys: Vec<Vec<u8>> = vec![];
    for pass in passes{
        rand::thread_rng().fill_bytes(&mut salt);
        keys.push(PBKDF2(&salt, &pass, 10000));
    }

    let mut bits = Vec::<u16>::new();

    for k in keys{
        let mut m: u16 = (k[1] >> 6) as u16;
        m += (k[0] << 2) as u16;
        bits.push(m);
    }
    let j_bits = json!(bits);

    let mut file = File::create("data/pass_res.json").unwrap();
    file.write_all(j_bits.to_string().as_bytes()).unwrap();

}

fn main() {
    // hkdf_test();
    pbkdf2_test();
}
