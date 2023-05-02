use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
//use curve25519_dalek::{edwards, digest, scalar};
use curve25519_dalek::montgomery::MontgomeryPoint;
//use curve25519_dalek::traits::{IsIdentity};

use crate::tools::random::rand64_bytes;

const ScalarSize: usize = 32;

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

pub fn sign(m: &[u8; ScalarSize], secret: &Scalar) -> (Scalar, Scalar){
    let base = constants::X25519_BASEPOINT;
    let k = rand64_bytes();
    let k = Scalar::from_bytes_mod_order_wide(&k);

    let mut flag = false;
    for i in 0..ScalarSize{
        flag |= k[i] != 0;
    }

    if !flag{
        panic!("Not valid nonce");
    }
    
    let Q = k * base;
    let r = Scalar::from_bytes_mod_order(*Q.as_bytes());
    let h = Scalar::from_bytes_mod_order(*m);
    let s = (h + secret * r) * Scalar::invert(&k);
    (r, s)
}

pub fn verify(m: &[u8; ScalarSize], r: &Scalar, s: &Scalar, pk: &MontgomeryPoint) -> bool{
    if r.eq(&Scalar::zero()) || s.eq(&Scalar::zero()){
        panic!("Invalid signature. r or s are not supposed to be 0");
    }   
    
    let h = Scalar::from_bytes_mod_order(*m);
    let u1 = h * Scalar::invert(s);
    let u2 = r * Scalar::invert(s);

    let base = constants::X25519_BASEPOINT;

    let Pl = (u1 * base).to_edwards(0).unwrap();
    let Pr = (u2 * pk).to_edwards(0).unwrap();
    let P = Pl + Pr;

    let res = Scalar::from_bytes_mod_order(*P.to_montgomery().as_bytes());
    res.eq(&r)
}
