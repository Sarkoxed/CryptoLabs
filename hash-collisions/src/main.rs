use std::time::Instant;

mod attacks;
mod tools;

use crate::attacks::{birthday_sha256, pollard_short, pollard_full, pollard_own_short, pollard_own_full};
use crate::tools::{hash, new_hash};

fn check_birthday(n: usize){
   for count in 1..n{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = birthday_sha256(count);
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

fn check_pollard(n: u8, m: usize, k: u8, pollard_type: fn(u8, usize, u8) -> Option<(Vec<u8>, Vec<u8>)>){
    let mut count = 1;
    while count < m{
        let now = Instant::now();
        let res = pollard_type(n, count, k);
                println!("Current number of bits: {}", count);
        match res{
            Some((x, y)) => {
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

fn main(){
    //check_birthday(25);
    check_pollard(20, 25, 10, pollard_full);
}

