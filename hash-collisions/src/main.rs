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

fn check_pollard1(n: u8, m: usize, k: u8){
    for count in 1..m as usize{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = pollard_short(n, count, k);
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

fn check_pollard2(n: u8, m: usize, k: u8){
    for count in 1..m as usize{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = pollard_full(n, count, k);
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

fn check_pollard3(n: u8, m: usize, k: u8){
    for count in 1..m as usize{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = pollard_own_short(n, count, k);
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

fn check_pollard4(n: u8, m: usize, k: u8){
    for count in 1..m as usize{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = pollard_own_full(n, count, k);
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

fn main(){
    //check_birthday(25);
    //check_pollard3(3, 25);
    let (x, y) = pollard_own_short(4, 8, 5);
    println!("{}, {}", hex::encode(x), hex::encode(y));
}

