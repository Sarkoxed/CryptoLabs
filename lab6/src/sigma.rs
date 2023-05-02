use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::tools::{GenKey, GetShared, sign, verify, rand_bytes};

use hmac::{Hmac, Mac, digest};
use sha2::Sha256;


const ScalarSize: usize = 32;
const R: usize = 16;
const BlockSize: usize = 16;

pub struct Party{
    pub id:              Vec<u8>,
    pub ecdsa_sk:        Scalar,
    pub ecdsa_pk:        MontgomeryPoint,

    pub ecdh_sk:         Scalar,
    pub ecdh_pk:         MontgomeryPoint,
    pub ecdh_sp:         MontgomeryPoint,

    pub k_m:             Vec<u8>,
    pub k_e:             Vec<u8>,

}

pub fn init_party(n: usize) -> Party{
    Party{
        id: rand_bytes(n), 
        ecdsa_sk: Scalar::zero(),
        ecdsa_pk: Identity::identity(),
        
        ecdh_sk: Scalar::zero(),
        ecdh_pk: Identity::identity(),
        ecdh_sp: Identity::identity(),

        k_m:     vec![],
        k_e:     vec![],
    }
}

pub fn init_ecdsa(x: &mut Party){
    (x.ecdsa_pk, x.ecdsa_sk) = GenKey();
}

pub fn sigma(A: &mut Party, B: &mut Party){
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
    (B.k_m, B.k_e) = (Vec::from(&prf_res[..BlockSize]), Vec::from(&prf_res[BlockSize..]));

    let mut m = [0u8; ScalarSize];
    for i in 0..ScalarSize{
        m[i] = A.ecdh_pk.as_bytes()[i] ^ B.ecdh_pk.as_bytes()[i];
    }

    let (Br, Bs) = sign(&m, &B.ecdsa_sk);
    let mut Bmac = Hmac::<Sha256>::new_from_slice(&B.k_m[..]).unwrap();
    Bmac.update(&B.id[..]);
    let Bmac = Bmac.finalize().into_bytes().to_vec();



    let mut mac = Hmac::<Sha256>::new_from_slice(&r[..]).unwrap();
    mac.update(A.ecdh_sp.as_bytes());
    let prf_res = mac.finalize().into_bytes();
    (A.k_m, A.k_e) = (Vec::from(&prf_res[..BlockSize]), Vec::from(&prf_res[BlockSize..]));
    
    let mut mac = Hmac::<Sha256>::new_from_slice(&A.k_m[..]).unwrap();
    mac.update(&B.id[..]);
    let _ = mac.verify_slice(&Bmac[..]);

    let res = verify(&m, &Br, &Bs, &B.ecdsa_pk);
    if !res{
        panic!("B EC signature is not valid");
    }

    let mut m = [0u8; ScalarSize];
    for i in 0..ScalarSize{
        m[i] = A.ecdh_pk.as_bytes()[i] ^ B.ecdh_pk.as_bytes()[i];
    }

    let (Ar, As) = sign(&m, &A.ecdsa_sk);
    let mut Amac = Hmac::<Sha256>::new_from_slice(&A.k_m[..]).unwrap();
    Amac.update(&A.id[..]);
    let Amac = Amac.finalize().into_bytes().to_vec();


    let mut mac = Hmac::<Sha256>::new_from_slice(&B.k_m[..]).unwrap();
    mac.update(&A.id[..]);
    let _ = mac.verify_slice(&Amac[..]);

    let res = verify(&m, &Ar, &As, &A.ecdsa_pk);
    if !res{
        panic!("B EC signature is not valid");
    }
}
