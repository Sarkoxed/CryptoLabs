use std::time::{Duration, Instant};
use std::fs::File;
use std::io::prelude::*;
use std::thread;

use rand::Rng; // 0.8.5
mod macs;
mod tools;

use aes::Aes128;
use cmac::{Cmac, Mac};
use hmac::{Hmac};
use sha2::{Sha256, Digest};

use crate::macs::{OMAC, HMAC}; //, hmac, truncmac};
use crate::tools::{randbytes};

fn test_omac(n: usize){
    for i in 0..n{
        let key = randbytes(16);
        let mut omac = OMAC{
            key: None,
            K1: None,
            K2: None,
            prevstate: None,
            curstate: None,
            update: true,
        };
        omac.SetKey(key.clone());
        let mut mac = Cmac::<Aes128>::new_from_slice(&key[..]).unwrap();
        for _ in 0..10{
            let num = rand::thread_rng().gen_range(1..100);
            let data = randbytes(num);
//            println!("data{} = {:?}", i, &data);
            omac.MacAddBlock(&data);
            mac.update(&data);
        }
        let res = omac.MacFinalize() == Vec::from(&mac.finalize().into_bytes()[..]);
        if !res{
            panic!("Not equal");
        }
        println!("{},{}", i, res);
    }
}

fn test_hmac(n: usize){
    for i in 0..n{
        let num = rand::thread_rng().gen_range(32..96);
        let key = randbytes(num);
        let mut hmac = HMAC{
            key: None,
            left: Sha256::new(),
            state: Sha256::new()
        };
        hmac.SetKey(key.clone());
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[..]).unwrap();
        for _ in 0..10{
            let num = rand::thread_rng().gen_range(1..100);
            let data = randbytes(num);
//            println!("data{} = {:?}", i, &data);
            hmac.MacAddBlock(&data);
            mac.update(&data);
        }
        let res = hmac.MacFinalize() == Vec::from(&mac.finalize().into_bytes()[..]);
        if !res{
            panic!("Not equal");
        }
        println!("{}, {}", i, res);
    }
}
 
fn main(){
    test_omac(100);
    //test_hmac(100);
}
