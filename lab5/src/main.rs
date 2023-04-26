mod authenc;

use crate::authenc::{AuthenticEncryptor, rand_bytes, Mode};

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
        result: None,
        mac: None,
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
        result: None,
        mac: None,
    };

    authenc.SetKey(key.clone());
    let dec = authenc.ProcessData(&ct);
    assert_eq!(dec, pt);

}

fn main() {
    test_enc_dec();
}
