use sha2::{Sha256, Digest};
const BlockSize: usize = 64;
const HashLen: usize = 32;
const HkdfKeyLen: usize = 32;
const PBKDFKeyLen: usize = 64;
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

pub fn HkdfExtract(xts: &Vec<u8>, skm: &Vec<u8>) -> Vec<u8>{
    HmacSha256(xts, skm)
}

pub fn long_to_bytes(mut n: u32, k: usize) -> Vec<u8>{
    let mut res: Vec<u8> = vec![0u8; k];
    let mut counter = k-1;
    loop{
        res[counter] = (n % 256) as u8;
        n /= 256;
        counter -= 1;
        if n == 0{
            break;
        }
    }
    for _ in res.len()..k{
        res.push(0);
    }
    res.reverse();
    res
}

pub fn HkdfExpand(prk: &Vec<u8>, lastKey: &Vec<u8>, ctx: &Vec<u8>, i: u32) -> Vec<u8>{
    let mut Ki: Vec<u8> = vec![];
    let mut rctx = lastKey.clone();
    rctx.append(&mut prk.clone());
    rctx.append(&mut long_to_bytes(i, 0));
    Ki = HmacSha256(prk, &rctx);
    Ki
}


pub fn PBKDF2(salt: &Vec<u8>, passw: &Vec<u8>, c_rounds: u16) -> Vec<u8>{
    let L = (PBKDFKeyLen + HashLen - 1)/ HashLen;
    let mut T = vec![];
    for i in 1..L+1{
        let mut exsalt = salt.clone();
        exsalt.append(&mut long_to_bytes(i as u32, 4));
        let mut Ti = HmacSha256(passw, &exsalt); 
        let mut Uc = Ti.clone();
        for _ in 1..c_rounds{
            let Ui = HmacSha256(passw, &Uc);
            for j in 0..HashLen{
                Ti[j] ^= Ui[j];
            }
            Uc = Ui;
        }
        T.append(&mut Ti);
    }
    Vec::from(&T[..PBKDFKeyLen])
}
