use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};
use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc;


use urandom;
use hex;

use sha256::{digest};

fn randbytes(x: &mut [u8]){
    let mut rng = urandom::new();
    for i in 0..x.len(){
        x[i] = rng.next::<u8>();
    }
}

fn lsb(h: &[u8], m: usize) -> String{
    if ((m + 7) / 8) > h.len(){
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

fn birthday_sha256(m_bits: usize) -> ([u8; 16], [u8; 16]){
    let mut pairs = HashMap::<String, [u8; 16]>::new();
    loop {
        let mut x = [0u8; 16];
        randbytes(&mut x);

        let h = match hex::decode(digest(&x)){
            Ok(val) => lsb(&val, m_bits), 
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


fn pollard_sha256(n_threads: u8, m_bits: usize) -> (Vec<u8>, Vec<u8>){ // , k_bits: usize
    if n_threads <= 1{
        panic!("Not enough threads");
    }

    let mut pairs = Arc::new(Mutex::new(HashMap::<String, [u8; 16]>::new()));
    let mut handles = vec![];
    
    let q = m_bits / 2 - (n_threads as f64).log2().floor() as usize;

    let (tx, rx) = mpsc::channel();
    for _ in 0..n_threads{
        let pairs = Arc::clone(&pairs);
        let txi = tx.clone();
        let handle = thread::spawn(move || {
            let states = vec![];

            let mut state = [0u8; 16];
            randbytes(&mut state);
            let mut state = Vec::from(state);
            let mut counter = 0;
            loop{
                state.push(0);                                   // TODO: how to store all the dist
                                                                 // points for all the threads
                                                                 // complete the channel thing 
                                                                 // complete the find for the first
                                                                 // thread
                                                                 // store or not the number of
                                                                 // thread
                let h = match hex::decode(digest(&state[..])){
                    Ok(val) => lsb(&val, m_bits), 
                    Err(error) => panic!("{error}"),
                };

                let mut map = match pairs.lock(){
                    Ok(val) => val,
                    Err(error) => panic!("{error}"),
                };

                let tmp = (*map).get(&h);
                if let Some(coll) = tmp{
                    return (*coll, x);
                }
                counter += 1;
            //*pairs.
            }
        });
        handles.push(handle);
    }

    for handle in handles{
        handle.join().unwrap();
    }
}

fn main(){
    //check_birthday();
    println!("{:?}", hex::decode(digest(b"\x85-\x08\xe4XRJ\x1c\x01\xe2\x8fS,\x9e\x19\xb5")).unwrap());
}
