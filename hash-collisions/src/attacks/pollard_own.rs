use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use std::time::Duration;

use crate::tools::{hash, hsb, lsb, new_hash, randbytes};

fn dist_point(h: &Vec<u8>, q: usize) -> bool {
    if q == 0 {
        return true;
    }
    let h = hsb(&h, q);
    for i in h {
        if i != 0 {
            return false;
        }
    }
    true
}

fn extend(h: &mut Vec<u8>, k: u8) {
    for _ in 0..k {
        h.push(0);
    }
}

pub fn pollard_own_short(n_threads: u8, m_bits: usize, k: u8) -> Option<(Vec<u8>, Vec<u8>)> {
    if n_threads <= 1 {
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, (Vec<u8>, u32)>::new()));
    let q = m_bits as i32 / 2 - (n_threads as f64).log2().floor() as i32;
    let q = if q > 0 { q as usize } else { 0 as usize };

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    for th in 0..n_threads {
        let pairs_f = Arc::clone(&pairs);
        let txi = tx.clone();

        let handle = thread::spawn(move || {
            let mut state = [0u8; 16];
            randbytes(&mut state);
            let mut state = Vec::from(state);
            extend(&mut state, k);

            let mut prev_dist = state.clone();
            let mut prev_counter: u32 = 0;

            let mut counter: u32 = 1;
            loop {
                if counter % 10000 == 0 {
                    // anti-cycle
                    let mut map = match pairs_f.lock() {
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };
                    let tmp = (*map).get(&vec![]);
                    if let Some(_prev) = tmp {
                        break;
                    }
                    drop(map);
                }

                let mut h = new_hash(&state, m_bits);
                extend(&mut h, k);
                if dist_point(&h, q) {
                    let mut map = match pairs_f.lock() {
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };
                    let tmp = (*map).get(&h);
                    if let Some(_prev) = tmp {
                        (*map).insert(vec![], (vec![], 0));
                        _ = txi.send((prev_dist, counter - prev_counter, h.clone()));
                        break;
                    } else {
                        (*map).insert(h.clone(), (prev_dist, counter - prev_counter));
                    }
                    prev_dist = h.clone();
                    prev_counter = counter;
                    drop(map);
                }
                state = h;
                counter += 1;
            }
        });
        handles.push(handle);
    }

    let (mut state1, i1, h) = match rx.recv() {
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    for (i, handle) in handles.into_iter().enumerate() {
        handle.join().unwrap();
    }

    let map = match pairs.lock() {
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    let (state2, i2) = map.get(&h).unwrap();
    let mut state2 = state2.clone();
    let i2 = *i2;

    for _ in 0..i1 - 1 {
        let h1 = new_hash(&state1, m_bits);
        state1 = h1;
        extend(&mut state1, k);
    }
    for _ in 0..i2 - 1 {
        let h2 = new_hash(&state2, m_bits);
        state2 = h2;
        extend(&mut state2, k);
    }

    assert_eq!(new_hash(&state1, m_bits), new_hash(&state2, m_bits));
    if state1 == state2 {
        return None;
    }
    Some((state1, state2))
}

pub fn pollard_own_full(n_threads: u8, m_bits: usize, k: u8) -> Option<(Vec<u8>, Vec<u8>)> {
    if n_threads <= 1 {
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, (Vec<u8>, u32)>::new()));
    let q = m_bits as i32 / 2 - (n_threads as f64).log2().floor() as i32;
    let q = if q > 0 { q as usize } else { 0 as usize };

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    for _th in 0..n_threads {
        let pairs_f = Arc::clone(&pairs);
        let txi = tx.clone();

        let handle = thread::spawn(move || {
            let mut state = [0u8; 16];
            randbytes(&mut state);
            let mut state = Vec::from(state);
            extend(&mut state, k);

            let mut prev_dist = state.clone();
            let mut prev_counter: u32 = 0;

            let mut counter: u32 = 1;
            loop {
                if counter % 10000 == 0 {
                    // anti-cycle
                    let mut map = match pairs_f.lock() {
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };
                    let tmp = (*map).get(&vec![]);
                    if let Some(_prev) = tmp {
                        break;
                    }
                    drop(map);
                }

                let mut h = hash(&state);
                let h_1 = lsb(&h, m_bits);
                extend(&mut h, k);

                if dist_point(&h, q) {
                    let mut map = match pairs_f.lock() {
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };

                    let tmp = (*map).get(&vec![]);
                    if let Some(_prev) = tmp {
                        break;
                    }

                    let tmp = (*map).get(&h_1);
                    if let Some(_prev) = tmp {
                        (*map).insert(vec![], (vec![], 0));
                        _ = txi.send((prev_dist, counter - prev_counter, h_1.clone()));
                        break;
                    } else {
                        (*map).insert(h_1.clone(), (prev_dist, counter - prev_counter));
                    }
                    prev_dist = h.clone();
                    prev_counter = counter;
                    drop(map);
                }
                state = h;
                counter += 1;
            }
        });
        handles.push(handle);
    }

    let (mut state1, i1, h) = match rx.recv() {
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    for (i, handle) in handles.into_iter().enumerate() {
        println!("{i}");
        handle.join().unwrap();
    }

    let map = match pairs.lock() {
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    let (state2, i2) = map.get(&h).unwrap();
    let mut state2 = state2.clone();
    let i2 = *i2;

    for _ in 0..i1 - 1 {
        let h1 = hash(&state1);
        state1 = h1;
        extend(&mut state1, k);
    }
    for _ in 0..i2 - 1 {
        let h2 = hash(&state2);
        state2 = h2;
        extend(&mut state2, k);
    }

    assert_eq!(new_hash(&state1, m_bits), new_hash(&state2, m_bits));
    if state1 == state2 {
        return None;
    }
    Some((state1, state2))
}
