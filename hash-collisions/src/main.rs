use std::time::Instant;

mod attacks;
use crate::attacks::{birthday_sha256, pollard_sha256, hash};

fn check_birthday(n: usize){
   for count in 1..n{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = birthday_sha256(count);
        println!("a = {}\nb = {}", hex::encode(&x), hex::encode(&y));
        let xt = hash(&x, count);
        let yt = hash(&y, count);
        println!("h(a) = {}\nh(b) = {}", hex::encode(&xt), hex::encode(&yt));
        assert_eq!(xt, yt);
        println!("Time elapsed: {:.10}\n-----------------------", now.elapsed().as_micros() as f64 / 1000000.0);
    }
}

fn main(){
    check_birthday(20);
}
