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

fn main(){
    //check_birthday(25);
    let (a, b) = pollard_full(4, 20);
}
