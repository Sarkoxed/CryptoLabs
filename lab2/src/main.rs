use std::time::{Instant};
use std::fs::File;
use std::io::prelude::*;

mod attacks;
mod tools;

use crate::attacks::{birthday_sha256, pollard_short, pollard_full, pollard_own_short, pollard_own_full};
use crate::tools::{hash, new_hash};

fn check_birthday(n_bits: usize){
   for count in 1..n_bits{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y, _) = birthday_sha256(count);
        println!("a = {}\nb = {}", hex::encode(&x), hex::encode(&y));
        let xt = hash(&x);
        let yt = hash(&y);
        println!("h(a) = {}\nh(b) = {}", hex::encode(&xt), hex::encode(&yt));
        let xt = new_hash(&x, count);
        let yt = new_hash(&y, count);
        println!("nh(a) = {}\nnh(b) = {}", hex::encode(&xt), hex::encode(&yt));
        
        assert_eq!(xt, yt);
        println!("Time elapsed: {:.10}\n-----------------------", now.elapsed().as_micros() as f64 / 1000000.0);
   }
}

fn check_pollard(n_threads: u8, m_bits: usize, pad_len: u8, pollard_type: fn(u8, usize, u8) -> Option<(Vec<u8>, Vec<u8>, usize)>){
    let mut count = 1;
    while count < m_bits{
        let now = Instant::now();
        let res = pollard_type(n_threads, count, pad_len);
        println!("Current number of bits: {}", count);
        match res{
            Some((x, y, _)) => {
                println!("a = {}\nb = {}", hex::encode(&x), hex::encode(&y));
                let xt = hash(&x);
                let yt = hash(&y);
                println!("h(a) = {}\nh(b) = {}", hex::encode(&xt), hex::encode(&yt));
                let xt = new_hash(&x, count);
                let yt = new_hash(&y, count);
                println!("nh(a) = {}\nnh(b) = {}", hex::encode(&xt), hex::encode(&yt));
                
                assert_eq!(xt, yt);
                println!("Time elapsed: {:.10}\n-----------------------", now.elapsed().as_micros() as f64 / 1000000.0);
                count += 1;
            },
            None => continue,
        }
    }
}

fn hashes_times_n_memory_birth(dirname: String){
    let file_path = format!("{}/specs", dirname);
    let mut specs = File::create(file_path).unwrap();
    specs.write_all(b"Bits\tAvgTime\tAvgMem").unwrap();
    for n_bit in 15..36{
        println!("Bits: {}/35", n_bit);
        let mut total_mem: u128 = 0;
        let mut total_time: u128 = 0;
    
        let file_path = format!("{}/collisions_{:2}_bit", dirname, n_bit);
        let mut file = File::create(file_path).unwrap();
        
        let mut count = 0;        
        while count < 200{
            println!("Round: {}/200", count + 1);
            let now = Instant::now();
            let (x, y, m) = birthday_sha256(n_bit);
            let end = now.elapsed().as_micros();

            total_mem += m as u128;
            total_time += end as u128;

            let x = hex::encode(x);
            let y = hex::encode(y);
            let res = x + &" " + &y + &"\n";
            file.write_all(res.as_bytes()).unwrap();
            count += 1;
        }
        
        let res_time = format!("{:.10}", total_time as f64 / (200.0 * 1000000.0));
        let res_mem = format!("{:.10}", total_mem as f64 / 200.0);
        let res = format!("{}\t{}\t{}\n", n_bit, res_time, res_mem);
        specs.write_all(res.as_bytes()).unwrap();
    }
}

fn hashes_times_n_memory_pollard(dirname: String, pollard_type: fn(u8, usize, u8) -> Option<(Vec<u8>, Vec<u8>, usize)>, threads: u8, kbytes: u8){
    let file_path = format!("{}/specs", dirname);
    let mut specs = File::create(file_path).unwrap();
    specs.write_all(b"Bits\tAvgTime\tAvgMem\n").unwrap();
    for n_bit in 15..36{
        println!("Bits: {}/35", n_bit);
        let mut total_mem: u128 = 0;
        let mut total_time: u128 = 0;
    
        let file_path = format!("{}/collisions_{:2}_bit", dirname, n_bit);
        let mut file = File::create(file_path).unwrap();
        
        let mut count = 0;        
        while count < 200{
            let now = Instant::now();
            let res = pollard_type(threads, n_bit, kbytes);
            match res{
                Some((x, y, m)) =>{
                    let end = now.elapsed().as_micros();
                    println!("Round: {}/200", count + 1);

                    total_mem += m as u128;
                    total_time += end as u128;

                    let x = hex::encode(x);
                    let y = hex::encode(y);
                    let res = x + &" " + &y + &"\n";
                    file.write_all(res.as_bytes()).unwrap();
                    count += 1;
                },
                None => {println!("NONE"); continue},
            }
        }
        
        let res_time = format!("{:.10}", total_time as f64 / (200.0 * 1000000.0));
        let res_mem = format!("{:.10}", total_mem as f64 / 200.0);
        let res = format!("{}\t{}\t{}\n", n_bit, res_time, res_mem);
        specs.write_all(res.as_bytes()).unwrap();
    }
}

fn main(){
    check_birthday(20);
    check_pollard(8, 20, 3, pollard_own_short);
    check_pollard(8, 20, 3, pollard_own_full);
    check_pollard(8, 20, 3, pollard_short);
    check_pollard(8, 20, 3, pollard_full);

    //hashes_times_n_memory_birth(String::from("data/birthday"));
    //hashes_times_n_memory_pollard(String::from("data/pollard_own_short"), pollard_own_short, 8, 6);
    //hashes_times_n_memory_pollard(String::from("data/pollard_own_full"), pollard_own_full, 8, 2);
    //hashes_times_n_memory_pollard(String::from("data/pollard_short"), pollard_short, 8, 2);
    //hashes_times_n_memory_pollard(String::from("data/pollard_full"), pollard_full, 8, 2);
}
