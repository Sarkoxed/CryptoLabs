mod sigma;
mod tools;

use crate::tools::{rand_bytes, AuthenticEncryptor, Mode, GenKey, sign};

fn main() {
    let (pk, sk) = GenKey();
    let m = [1; 32];
    sign(m, &sk);    
}
