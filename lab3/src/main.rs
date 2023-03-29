use std::time::{Duration, Instant};
use std::fs::File;
use std::io::prelude::*;
use std::thread;

use rand::Rng; // 0.8.5
mod macs;
mod tools;

use crate::macs::{OMAC}; //, hmac, truncmac};
use crate::tools::{randbytes};


fn main(){
    let key = randbytes(16);
    println!("key = {:?}", &key);

    let mut omac = OMAC{
        key: None,
        K1: None,
        K2: None,
        prevstate: None,
        curstate: None,
        update: true,
    };
    omac.SetKey(key);
    
    for i in 0..10{
        let num = rand::thread_rng().gen_range(0..100);
        let data = randbytes(num);
        println!("data{} = {:?}", i, &data);
        omac.MacAddBlock(&data);
    }
    println!("{:?}", omac.MacFinalize());
}
