use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::tools::{GenKey, GetShared, rand_bytes};

use hmac::{Hmac, Mac, digest};
use sha2::Sha256;


const ScalarSize: usize = 64;
const R: usize = 16;
const BlockSize: usize = 16;

pub struct Party{
    pub ecdsa_sk:        Scalar,
    pub ecdsa_pk:        MontgomeryPoint,

    pub ecdh_sk:         Scalar,
    pub ecdh_pk:         MontgomeryPoint,
    pub ecdh_sp:         MontgomeryPoint,
}

pub fn init_party() -> Party{
    Party{
        ecdsa_sk: Scalar::from_bytes_mod_order_wide(&[0u8; ScalarSize]),
        ecdsa_pk: Identity::identity(),
        
        ecdh_sk: Scalar::from_bytes_mod_order_wide(&[0u8; ScalarSize]),
        ecdh_pk: Identity::identity(),
        ecdh_sp: Identity::identity(),
    }
}

fn init_ecdsa(A: &mut Party, B: &mut Party){
    (A.ecdsa_pk, A.ecdsa_sk) = GenKey();
    (B.ecdsa_pk, B.ecdsa_sk) = GenKey();
}

fn sigma(A: &mut Party, B: &mut Party){
    (A.ecdh_pk, A.ecdh_sk) = GenKey();
    let r_A = rand_bytes(R);

    (B.ecdh_pk, B.ecdh_sk) = GenKey();
    let mut r_B = rand_bytes(R);
    B.ecdh_sp = GetShared(&B.ecdh_sk, &A.ecdh_pk);
    
    let mut r = r_A.clone();
    r.append(&mut r_B);
    
    let mut mac = Hmac::<Sha256>::new_from_slice(&r[..]).unwrap();
    mac.update(B.ecdh_sp.as_bytes());
    let prf_res = mac.finalize().into_bytes();

    let (k_m, k_e) = (&prf_res[..BlockSize], &prf_res[BlockSize..]);
}
