use std::time::{Duration, Instant};
use std::fs::File;
use std::io::prelude::*;
use std::thread;

mod macs;
mod tools;

use crate::macs::{OMAC}; //, hmac, truncmac};
use crate::tools::{randbytes};


fn main(){
    let data = urandom(16);
    let key = urandom(16);
    println!("Hello, world!");
    println!("{:?}, {:?}", data, key);
}
