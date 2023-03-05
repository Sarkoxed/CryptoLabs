use std::collections::HashMap;

use crate::tools::{new_hash, randbytes};

pub fn birthday_sha256(m_bits: usize) -> (Vec<u8>, Vec<u8>) {
    let mut pairs = HashMap::<Vec<u8>, Vec<u8>>::new();
    loop {
        let mut x = [0u8; 16];
        randbytes(&mut x);
        let x = Vec::from(x);

        let h = new_hash(&x, m_bits);
        let tmp = pairs.get(&h);
        _ = match tmp {
            Some(coll) => return (coll.clone(), x),
            None => pairs.insert(h, x),
        }
    }
}
