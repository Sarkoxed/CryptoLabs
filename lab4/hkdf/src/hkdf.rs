use sha2::{Sha256, Digest};
use rand_chacha::ChaCha20Rng;

const BlockSize: usize = 64;
const HashLen: usize = 32;
const KeyLen: usize = 32;
const OPAD: u8 = 0x5c;
const IPAD: u8 = 0x36;

fn HmacSha256(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8>{
    let mut right: Vec<u8>;
    if key.len() > BlockSize{
        let mut hasher = Sha256::new();
        hasher.update(&key);
        right = hasher.finalize().to_vec();
    }
    else{
        right = key.clone();
    }
    while right.len() < BlockSize{
        right.push(0);
    }
    let mut left = right.clone();
    for i in 0..BlockSize{
        left[i] ^= OPAD;
        right[i] ^= IPAD;
    }

    let mut hasher_right = Sha256::new();
    hasher_right.update(right);
    hasher_right.update(data);
    right = hasher_right.finalize().to_vec();

    let mut hasher_left = Sha256::new();
    hasher_left.update(left);
    hasher_left.update(right);
    hasher_left.finalize().to_vec()
}

fn HkdfExtract(xts: &Vec<u8>, skm: &Vec<u8>) -> Vec<u8>{
    HmacSha256(xts, skm)
}

fn long_to_bytes(n: u32) -> Vec<u8>{
    let res: Vec<u8> = vec![];
    loop{
        res.push((n % 256) as u8);
        n /= 256;
        if n == 0{
            break;
        }
    }
    res.reverse();
    res
}

fn HkdfExpand(prk: &Vec<u8>, lastKey: &Vec<u8>, ctx: &Vec<u8>, i: u32) -> Vec<u8>{
    let mut Ki: Vec<u8> = vec![];
    for n in 0..i{
        let mut rctx = ctx.clone();
        rctx.append(&mut long_to_bytes(n));
        Ki = HmacSha256(prk, &rctx);
    }
    Ki
}

