mod tools;
mod sigma;
use crate::sigma::{init_party, init_ecdsa, sigma, encrypt, decrypt};

fn main() {
    let mut A = init_party(16);
    let mut B = init_party(16);

    init_ecdsa(&mut A);
    init_ecdsa(&mut B);

    A.o_ecdsa_pk = B.ecdsa_pk.clone();
    B.o_ecdsa_pk = A.ecdsa_pk.clone();

    sigma(&mut A, &mut B);
    let mA: Vec<u8> = vec![65, 98, 111, 98, 97, 32, 115, 97, 121, 115, 32, 104, 101, 108, 108, 111, 32, 116, 111, 32, 66, 111, 97, 98, 97];
    let ct = encrypt(&A, &mA);
    let mB = decrypt(&B, &ct);
    assert_eq!(mA, mB);
}
