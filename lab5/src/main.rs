mod authenc;

use crate::authenc::{AuthenticEncryptor, rand_bytes, Mode};

use std::fs;
use std::fs::File;

fn test_enc_dec(){
    let key = rand_bytes(32);
    let pt: Vec<u8> = vec![72, 101, 108, 108, 111, 44, 32, 65, 98, 111, 98, 97, 46, 32, 73, 39, 109, 32, 115, 117, 115, 33];
    let mut authenc = AuthenticEncryptor{
        mode: Mode::Enc,
        counter: None,
        hmac: None,
        cipher: None,
        enc_state: None,
        nonce: None,
    };

    authenc.SetKey(key.clone());
    let ct = authenc.ProcessData(&pt);
    println!("key = {:?}", &key);
    println!("pt = {:?}", &pt);
    println!("ct = {:?}", &ct);
    
    let mut authenc = AuthenticEncryptor{
        mode: Mode::Dec,
        counter: None,
        hmac: None,
        cipher: None,
        enc_state: None,
        nonce: None,
    };

    authenc.SetKey(key.clone());
    let dec = authenc.ProcessData(&ct);
    assert_eq!(dec, pt);

}

fn main() {
    //test_enc_dec();

    let fc = fs::read("data/lab5.pdf").unwrap();
    let key = fs::read("data/lab5.key").unwrap();
    let mut authenc = AuthenticEncryptor{
        mode: Mode::Enc,
        counter: None,
        hmac: None,
        cipher: None,
        enc_state: None,
        nonce: None,
    };
    authenc.SetKey(key);
    let ct = authenc.ProcessData(&fc);
    fs::write("data/lab5.enc", &ct).unwrap();

    let fc = fs::read("data/lab5.enc").unwrap();
    let key = fs::read("data/lab5.key").unwrap();
    let mut authenc = AuthenticEncryptor{
        mode: Mode::Dec,
        counter: None,
        hmac: None,
        cipher: None,
        enc_state: None,
        nonce: None,
    };
    authenc.SetKey(key);
    let pt = authenc.ProcessData(&fc);
    fs::write("data/lab5.dec", &pt).unwrap();
}
