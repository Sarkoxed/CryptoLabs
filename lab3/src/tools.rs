use std::fs::File;
use std::io::prelude::*;

pub fn randbytes(n: usize) -> Vec<u8>{
    let mut f = File::open("/dev/urandom").expect("Can't read anything");
    let mut res = vec![0u8; n];
    let m = f.read(&mut res[..]).expect("{m} bytes instead of {n}");
    res
}
