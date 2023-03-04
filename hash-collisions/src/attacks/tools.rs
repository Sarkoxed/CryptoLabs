use sha256::{digest};
use urandom;
use hex;

pub fn randbytes(x: &mut [u8]){
    let mut rng = urandom::new();
    for i in 0..x.len(){
        x[i] = rng.next::<u8>();
    }
}

fn lsb(h: &[u8], m: usize) -> String{
    let m_bytes = (m + 7) / 8;
    if m_bytes > h.len(){
        panic!("Wrong number of bits");
    }
    let mut res = Vec::from(&h[h.len() - m_bytes..]);
    res[0] = res[0] % (1 << (m % 8));
    hex::encode(res)
}

pub fn hsb(h: &[u8], m: usize) -> String{
    let m_bytes = (m + 7) / 8;
    if m_bytes > h.len(){
        panic!("Wrong number of bits");
    }
    let mut res = Vec::from(&h[..m_bytes]);
    let last = res.len() - 1;
    res[last] = res[last] >> (m % 8);
    hex::encode(res)
}

pub fn hash(s: &Vec<u8>, m_bits: usize) -> Vec<u8>{
    match hex::decode(digest(&s[..])){
        Ok(val) => Vec::from(lsb(&val, m_bits)),
        Err(error) => panic!("{error}"),
    }
}
