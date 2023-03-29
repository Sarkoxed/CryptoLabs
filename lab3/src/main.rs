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
    }
}

fn check_fail_omac(){
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
    let data = randbytes(24);
    omac.MacAddBlock(&data);
    let tag = omac.MacFinalize();
    let mut tag1 = tag.clone();           
    let num = rand::thread_rng().gen_range(0..128);
    let res1 = omac.VerifyMac(&data, &tag);
    
    tag1[num / 8] ^= 1 << (num % 8);
    let res2 = omac.VerifyMac(&data, &tag1);
    if !res1 || res2{
        panic!("Tag forgery..");
    }

}

fn check_fail_hmac(){
    let num = rand::thread_rng().gen_range(48..96);
    let key = randbytes(num);
    let mut hmac = HMAC{
        key: None,
        left: Sha256::new(),
        state: Sha256::new()
    };
    hmac.SetKey(key.clone());
    let data = randbytes(48);
    hmac.MacAddBlock(&data);
    let tag = hmac.MacFinalize();
    let mut tag1 = tag.clone();           
    let num = rand::thread_rng().gen_range(0..256);
    let res1 = hmac.VerifyMac(&data, &tag);
    
    tag1[num / 8] ^= 1 << (num % 8);
    let res2 = hmac.VerifyMac(&data, &tag1);
    if !res1 || res2{
        panic!("Tag forgery..");
    }
}

fn check_fail_tcbc(){
    let key = randbytes(16);
    let mut tcbc = TCBC{
        key: None,
        prevstate: None,
        curstate: None, 
        update: true
    };
    tcbc.SetKey(key.clone());
    let data = randbytes(12);
    tcbc.MacAddBlock(&data);
    let tag = tcbc.MacFinalize();
    let mut tag1 = tag.clone();           
    let num = rand::thread_rng().gen_range(0..64);
    let res1 = tcbc.VerifyMac(&data, &tag);
    
    tag1[num / 8] ^= 1 << (num % 8);
    let res2 = tcbc.VerifyMac(&data, &tag1);
    if !res1 || res2{
        panic!("Tag forgery..");
    }
}

fn timing_omac(dirname: String, m: usize){
    let file_path = format!("{}/specs", dirname);
    let mut specs = File::create(file_path).unwrap();
    specs.write_all(b"Bytes   AvgTime\n").unwrap();

    let lengths = vec![100, 1000, 10000, 100000, 1024000];

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

    for n in 0..lengths.len(){
        println!("Bytes: {}", lengths[n]);
        let mut total_time: u128 = 0;
    
        let mut count = 0;        
        while count < m{
            let data = randbytes(lengths[n]);
            let now = Instant::now();
            _ = omac.ComputeMac(&data);
            let end = now.elapsed().as_micros();
 //           println!("Round: {}/{}", count + 1, m);
            total_time += end as u128;
            count += 1;
            omac.reset();
        }
        
        let res_time = format!("{:.10}", total_time as f64 / ((m as f64) * 1000000.0));
        let res = format!("{:<8}{}\n", lengths[n], res_time);
        specs.write_all(res.as_bytes()).unwrap();
    }
}

fn timing_hmac(dirname: String, m: usize){
    let file_path = format!("{}/specs", dirname);
    let mut specs = File::create(file_path).unwrap();
    specs.write_all(b"Bytes   AvgTime\n").unwrap();

    let lengths = vec![100, 1000, 10000, 100000, 1024000];
    
    let num = rand::thread_rng().gen_range(48..96);
    let key = randbytes(num);
    let mut hmac = HMAC{
        key: None,
        left: Sha256::new(),
        state: Sha256::new()
    };
    hmac.SetKey(key.clone());

    for n in 0..lengths.len(){
        println!("Bytes: {}", lengths[n]);
        let mut total_time: u128 = 0;
    
        let mut count = 0;        
        while count < m{
            let data = randbytes(lengths[n]);
            let now = Instant::now();
            _ = hmac.ComputeMac(&data);
            let end = now.elapsed().as_micros();
//            println!("Round: {}/{}", count + 1, m);
            total_time += end as u128;
            count += 1;
            hmac.SetKey(key.clone());
        }
        
        let res_time = format!("{:.10}", total_time as f64 / ((m as f64) * 1000000.0));
        let res = format!("{:<8}{}\n", lengths[n], res_time);
        specs.write_all(res.as_bytes()).unwrap();
    }
}


fn timing_tcbc(dirname: String, m: usize){
    let file_path = format!("{}/specs", dirname);
    let mut specs = File::create(file_path).unwrap();
    specs.write_all(b"Bytes   AvgTime\n").unwrap();

    let lengths = vec![100, 1000, 10000, 100000, 1024000];
    
    let key = randbytes(16);
    let mut tcbc = TCBC{
        key: None,
        prevstate: None,
        curstate: None,
        update: true
    };
    tcbc.SetKey(key.clone());

    for n in 0..lengths.len(){
        println!("Bytes: {}", lengths[n]);
        let mut total_time: u128 = 0;
    
        let mut count = 0;        
        while count < m{
            let data = randbytes(lengths[n]);
            let now = Instant::now();
            _ = tcbc.ComputeMac(&data);
            let end = now.elapsed().as_micros();
//            println!("Round: {}/{}", count + 1,m);
            total_time += end as u128;
            count += 1;
            tcbc.reset();
        }
        
        let res_time = format!("{:.10}", total_time as f64 / ((m as f64) * 1000000.0));
        let res = format!("{:<8}{}\n", lengths[n], res_time);
        specs.write_all(res.as_bytes()).unwrap();
    }
}
fn main(){
    test_omac(1000);
    test_hmac(1000);
    test_tcbc(1000);

    println!("Tests passed");
    for _ in 0..1000{
        check_fail_omac();
        check_fail_hmac();
        check_fail_tcbc();
    }
    println!("Checks passed");
    timing_omac(String::from("data/omac"), 1000);
    timing_hmac(String::from("data/hmac"), 1000);
    timing_tcbc(String::from("data/tcbc"), 1000);
}
