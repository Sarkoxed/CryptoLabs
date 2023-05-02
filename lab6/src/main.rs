mod tools;
use crate::tools::{rand_bytes, AuthenticEncryptor, Mode, GenKey, sign};

mod sigma;
use crate::sigma::{Party, init_party, init_ecdsa, sigma};

fn main() {
    let mut A = init_party(16);
    let mut B = init_party(16);

    init_ecdsa(&mut A);
    init_ecdsa(&mut B);

    sigma(&mut A, &mut B);
}
