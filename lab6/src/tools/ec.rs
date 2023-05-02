use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
//use curve25519_dalek::{edwards, digest, scalar};
use curve25519_dalek::montgomery::MontgomeryPoint;
//use curve25519_dalek::traits::{IsIdentity};

use crate::tools::random::rand64_bytes;



pub fn GenKey() -> (MontgomeryPoint, Scalar){
    let base = constants::X25519_BASEPOINT;

    let secret_b = rand64_bytes();
    let sk = Scalar::from_bytes_mod_order_wide(&secret_b); 
    let pk = sk * base;
    (pk, sk)
}


pub fn GetShared(sk: &Scalar, sharedPoint: &MontgomeryPoint) -> MontgomeryPoint{
    sk * sharedPoint
}

pub fn sign(m: [u8; 32], secret: &Scalar) -> (Scalar, Scalar){
    let base = constants::X25519_BASEPOINT;
    let k = rand64_bytes();
    let k = Scalar::from_bytes_mod_order_wide(&k);

    let mut flag = false;
    let mut flag1 = false;
    for i in 0..32{
        if k[i] != 0{
            flag = true;
        }
        else{
            flag1 = false;
        }
    }

    if !flag{
        panic!("Not valid nonce");
    }
    
    let Q = k * base;
    let r = Scalar::from_bytes_mod_order(*Q.as_bytes());
    let h = Scalar::from_bytes_mod_order(m);
    let s = (h + secret * r) * Scalar::invert(&k);
    (r, s)
}