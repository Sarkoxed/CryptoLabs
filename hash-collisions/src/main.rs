use std::collections::HashMap;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

use urandom;
use hex;

use sha256::{digest};

fn randbytes(x: &mut [u8]){
    let mut rng = urandom::new();
    for i in 0..x.len(){
        x[i] = rng.next::<u8>();
    }
}

fn lsb(h: &[u8], m: u8) -> String{
    if ((m + 7) / 8) > h.len() as u8{
        panic!("Wrong number of bits");
    }

    let mut res = String::new();
    for i in 0..m{
        let index = (i / 8) as usize;
        let tmp = (h[h.len() - index - 1] >> (i % 8)) & 1;
        res = tmp.to_string() + &res;
    }
    res
}

fn birthday_sha256(m: u8) -> ([u8; 16], [u8; 16]){
    let mut pairs = HashMap::<String, [u8; 16]>::new();
    loop {
        let mut x = [0u8; 16];
        randbytes(&mut x);

        let h = match hex::decode(digest(&x)){
            Ok(val) => lsb(&val, m), 
            Err(error) => panic!("{error}"),
        };

        let tmp = pairs.get(&h);
        _ = match tmp{
            Some(coll) => return (*coll, x),
            None => pairs.insert(h, x),
        }
    }
}    

fn check_birthday(){
    //let mut index = String::new();
    //io::stdin().read_line(&mut index).expect("Failed to read line");
    //let index: u8 = index.trim().parse().expect("Index entered was not a num");
    for count in 1..30{
        let now = Instant::now();
        println!("Current number of bits: {}", count);
        let (x, y) = birthday_sha256(count);
        println!("a = {}\nb = {}", hex::encode(x), hex::encode(y));
        let xt = lsb(&hex::decode(digest(&x)).unwrap(), count);
        let yt = lsb(&hex::decode(digest(&y)).unwrap(), count);
        println!("h(a) = {xt}\nh(b) = {yt}");
        assert_eq!(xt, yt);
        println!("Time elapsed: {:.10}\n-----------------------", now.elapsed().as_micros() as f64 / 1000000.0);
    }
}

fn pollard(){}

fn main(){
    //check_birthday();
    println!("{:?}", hex::decode(digest(b"\x85-\x08\xe4XRJ\x1c\x01\xe2\x8fS,\x9e\x19\xb5")).unwrap());
}
