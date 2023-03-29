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
//use cbc_mac::{CbcMac};
use sha2::{Sha256, Digest};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;



use crate::macs::{OMAC, HMAC, TCBC};
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

fn test_tcbc(n: usize){
    for i in 0..n{
        let key = randbytes(16);
        let mut tcbc = TCBC{
            key: None,
            prevstate: None,
            curstate: None,
            update: true
        };
        tcbc.SetKey(key.clone());

        //let mut mac = CbcMac::<Aes128>::new_from_slice(&key[..]).unwrap();
        let iv = [0u8; 16];
        let mut key1 = [0u8; 16];
        for i in 0..16{
            key1[i] = key[i];
        }
        let cipher = Aes128CbcEnc::new(&key1.into(), &iv.into());
        let mut dataf = vec![];
            
        for j in 0..5{
            let num = rand::thread_rng().gen_range(1..16); //00);
            let mut data = randbytes(num);
            tcbc.MacAddBlock(&data);
            dataf.append(&mut data);
        }
        
        let len;
        if dataf.len() % 16 == 0{
            len = dataf.len() + 16;
        }
        else{
            len = ((dataf.len() + 15) / 16) * 16;
        }
        let mut buf = vec![0u8; len];
        let h2 = cipher.encrypt_padded_b2b_mut::<Pkcs7>(&dataf, &mut buf).unwrap();

        let a = tcbc.MacFinalize();
        let b = Vec::from(&h2[len-16..len-8]); 

        let res = a == b;
        if !res{
            panic!("Not equal");
        }
        //println!("{}, {}", i, res);
    }
}
 
fn main(){
    //test_omac(100);
    //test_hmac(100);
    test_tcbc(1000);
}
