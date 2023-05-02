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

    pub o_id:            Vec<u8>,
    pub o_ecdsa_pk:      MontgomeryPoint,
    pub o_ecdh_pk:       MontgomeryPoint,
}

pub fn init_party(n: usize) -> Party{
    Party{
        id: rand_bytes(n), 
        ecdsa_sk:   Scalar::zero(),
        ecdsa_pk:   Identity::identity(),
        
        ecdh_sk:    Scalar::zero(),
        ecdh_pk:    Identity::identity(),
        ecdh_sp:    Identity::identity(),

        k_m:        vec![],
        k_e:        vec![],

        o_id:       vec![],
        o_ecdsa_pk: Identity::identity(),
        o_ecdh_pk:  Identity::identity(),
    }
}

pub fn init_ecdsa(x: &mut Party){
    (x.ecdsa_pk, x.ecdsa_sk) = GenKey();
}


pub fn init_ecdh(x: &mut Party){
    (x.ecdh_pk, x.ecdh_sk) = GenKey();
}

pub fn init_session_keys(x: &mut Party, r1: &Vec<u8>, r2: &mut Vec<u8>){
    let mut r = r1.clone();
    r.append(r2);

    let mut mac = Hmac::<Sha256>::new_from_slice(&r[..]).unwrap();
    mac.update(x.ecdh_sp.as_bytes());
    let prf_res = mac.finalize().into_bytes();
    (x.k_m, x.k_e) = (Vec::from(&prf_res[..BlockSize]), Vec::from(&prf_res[BlockSize..]));
}

pub fn sign_public_keys(x: &mut Party) -> (Scalar, Scalar){
    let mut m = x.o_ecdh_pk.as_bytes().to_vec();
    m.append(&mut x.ecdh_pk.as_bytes().to_vec());
    let m: [u8; 2 * ScalarSize] = m.try_into().unwrap();
    sign(&m, &x.ecdsa_sk)
} 

pub fn verify_public_keys(x: &mut Party, signature: &(Scalar, Scalar)){
    let (r, s) = signature;
    
    let mut m = x.ecdh_pk.as_bytes().to_vec();
    m.append(&mut x.o_ecdh_pk.as_bytes().to_vec());
    let m: [u8; 2 * ScalarSize] = m.try_into().unwrap();
 
    let res = verify(&m, &r, &s, &x.o_ecdsa_pk);
    if !res{
        panic!("EC signature is not valid");
    }
}

pub fn get_mac(x: &mut Party) -> Vec<u8>{
    let mut mac = Hmac::<Sha256>::new_from_slice(&x.k_m[..]).unwrap();
    mac.update(&x.id[..]);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_mac(x: &mut Party, o_mac: &Vec<u8>){
    let mut mac = Hmac::<Sha256>::new_from_slice(&x.k_m[..]).unwrap();
    mac.update(&x.o_id[..]);
    let _ = mac.verify_slice(&o_mac[..]);
}

pub fn sigma(A: &mut Party, B: &mut Party){
    init_ecdh(A);
    let r_A = rand_bytes(R);
    B.o_ecdh_pk = A.ecdh_pk.clone();


    init_ecdh(B);
    let mut r_B = rand_bytes(R);
    B.ecdh_sp = GetShared(&B.ecdh_sk, &A.ecdh_pk);
    init_session_keys(B, &r_A, &mut r_B);
    sign_public_keys(B);
    let sign_B = sign_public_keys(B);
    let mac_B = get_mac(B);
   

    A.ecdh_sp = GetShared(&A.ecdh_sk, &B.ecdh_pk);
    init_session_keys(A, &r_A, &mut r_B);
    verify_public_keys(A, &sign_B);
    verify_mac(A, &mac_B);
    let sign_A = sign_public_keys(A);
    let mac_A = get_mac(A);

    verify_public_keys(B, &sign_A);
    verify_mac(B, &mac_A);
}
