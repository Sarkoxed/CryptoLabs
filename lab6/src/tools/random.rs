use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

pub fn rand_bytes(n: usize) -> Vec<u8>{
    let rand = ChaCha20Rng::from_entropy();
    let mut res = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut res);
    res
}

pub fn rand64_bytes() -> [u8; 64]{
    let mut res = [0u8; 64];
    let rand = ChaCha20Rng::from_entropy();
    rand::thread_rng().fill_bytes(&mut res);
    res
}
