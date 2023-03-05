use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

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

pub fn pollard_short(n_threads: u8, m_bits: usize, k: u8) -> Option<(Vec<u8>, Vec<u8>)> {
    if n_threads <= 1 {
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, (u32, u8)>::new()));
    let q = m_bits as i32 / 2 - (n_threads as f64).log2().floor() as i32;
    let q = if q > 0 { q as usize } else { 0 as usize };

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    let mut inits = vec![];
    for th in 0..n_threads {
        let pairs_f = Arc::clone(&pairs);
        let txi = tx.clone();

        let mut state = [0u8; 16];
        randbytes(&mut state);
        let mut state = Vec::from(state);
        inits.push(state.clone());

        let handle = thread::spawn(move || {
            extend(&mut state, k);
            let mut counter: u32 = 1;
            loop {
                if counter % 10000 == 0 {
                    // anti-cycle
                    let map = match pairs_f.lock() {
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

                    let tmp = (*map).get(&vec![]);
                    if let Some(_prev) = tmp {
                        // well to stop we have to wait until the dist
                        // point
                        break;
                    }

                    let tmp = (*map).get(&h);
                    if let Some(prev) = tmp {
                        let (c2, th2) = prev;
                        let c2 = *c2;
                        let th2 = *th2;
                        (*map).insert(vec![], (0, 0));
                        _ = txi.send((th, counter, th2, c2));
                        break;
                    } else {
                        (*map).insert(h.clone(), (counter, th));
                    }
                    drop(map);
                }
                state = h;
                counter += 1;
            }
        });
        handles.push(handle);
    }

    let (mut th1, mut i1, mut th2, mut i2) = match rx.recv() {
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    for (_, handle) in handles.into_iter().enumerate() {
        handle.join().unwrap();
    }

    if i1 > i2 {
        (i1, i2) = (i2, i1);
        (th1, th2) = (th2, th1);
    }

    let d = i2 - i1;

    let mut state1 = (&inits[th1 as usize]).clone();
    let mut state2 = (&inits[th2 as usize]).clone();

    extend(&mut state1, k);
    extend(&mut state2, k);

    for _ in 0..d {
        state2 = new_hash(&state2, m_bits);
        extend(&mut state2, k);
    }

    loop {
        let h1 = new_hash(&state1, m_bits);
        let h2 = new_hash(&state2, m_bits);

        if h1 == h2 {
            break;
        }

        state1 = h1;
        state2 = h2;
        extend(&mut state1, k);
        extend(&mut state2, k);
    }

    assert_eq!(new_hash(&state1, m_bits), new_hash(&state2, m_bits));
    if state1 == state2 {
        return None;
    }
    Some((state1, state2))
}

pub fn pollard_full(n_threads: u8, m_bits: usize, k: u8) -> Option<(Vec<u8>, Vec<u8>)> {
    // , k_bits: usize
    if n_threads <= 1 {
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, (u32, u8)>::new()));
    let q = m_bits as i32 / 2 - (n_threads as f64).log2().floor() as i32;
    let q = if q > 0 { q as usize } else { 0 as usize };

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    let mut inits = vec![];
    for th in 0..n_threads {
        let pairs_f = Arc::clone(&pairs);
        let txi = tx.clone();

        let mut state = [0u8; 16];
        randbytes(&mut state);
        let mut state = Vec::from(state);
        inits.push(state.clone());

        let handle = thread::spawn(move || {
            extend(&mut state, k);
            let mut counter: u32 = 1;
            loop {
                if counter % 10000 == 0 {
                    // anti-cycle
                    let map = match pairs_f.lock() {
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
                    if let Some(prev) = tmp {
                        let (c2, th2) = prev;
                        let c2 = *c2;
                        let th2 = *th2;
                        (*map).insert(vec![], (0, 0));
                        _ = txi.send((th, counter, th2, c2));
                        break;
                    } else {
                        (*map).insert(h_1.clone(), (counter, th));
                    }
                    drop(map);
                }
                state = h;
                counter += 1;
            }
        });
        handles.push(handle);
    }

    let (mut th1, mut i1, mut th2, mut i2) = match rx.recv() {
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    for (_, handle) in handles.into_iter().enumerate() {
        handle.join().unwrap();
    }

    if i1 > i2 {
        (i1, i2) = (i2, i1);
        (th1, th2) = (th2, th1);
    }

    let d = i2 - i1;

    let mut state1 = (&inits[th1 as usize]).clone();
    let mut state2 = (&inits[th2 as usize]).clone();
    extend(&mut state1, k);
    extend(&mut state2, k);

    for _ in 0..d {
        state2 = hash(&state2);
        extend(&mut state2, k);
    }

    loop {
        let h1 = hash(&state1);
        let h2 = hash(&state2);

        if lsb(&h1, m_bits) == lsb(&h2, m_bits) {
            break;
        }

        state1 = h1;
        state2 = h2;
        extend(&mut state1, k);
        extend(&mut state2, k);
    }

    assert_eq!(new_hash(&state1, m_bits), new_hash(&state2, m_bits));
    if state1 == state2 {
        return None;
    }
    Some((state1, state2))
}
