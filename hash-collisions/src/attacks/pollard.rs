use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc;
use std::collections::HashMap;

use crate::attacks::{hash, randbytes};

fn dist_point(h: &Vec<u8>, q: usize) -> bool{
    for i in 0..q{
        if h[i] != b'0'{
            return false
        }
    }
    true
}

pub fn pollard_sha256(n_threads: u8, m_bits: usize) -> (Vec<u8>, Vec<u8>){ // , k_bits: usize
    if n_threads <= 1{
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, u8>::new()));
    let mut states = vec![];
    for _ in 0..n_threads{
        states.push(Vec::new());
    }

    let q = m_bits / 2 - (n_threads as f64).log2().floor() as usize;

    let (tx, rx) = mpsc::channel();

    for th in 0..n_threads{
        let pairs = Arc::clone(&pairs);
        let txi = tx.clone();
        let mut state_per_thread = &states[th as usize];

        thread::spawn(move || {
            let mut state = [0u8; 16];
            randbytes(&mut state);
            let mut state = Vec::from(state);
            let mut counter: u32 = 0;
            loop{
                state.push(0);   
                let h = hash(&state, m_bits); 

                if dist_point(&h, q){
                    let mut map = match pairs.lock(){
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };

                    state_per_thread.push((state.clone(), counter));

                    let tmp = (*map).get(&h);
                    if let Some(th2) = tmp{
                        let (st2, i2) = state_per_thread[state_per_thread.len() - 2];
                        txi.send((st2, i2, hex::decode(&h).unwrap(), th, *th2));
                    }else{
                        (*map).insert(h.clone(), th);
                    }
                    drop(map);
                }
                state = h;
                counter += 1;
            }
        });
    }

    let (mut state1, mut i1, end_state, _, th2) = match rx.recv(){
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };

    let mut i2: u32 = 0;
    let mut state2 = vec![];

    for i in 0..states[th2 as usize].len(){
        let (state, _) = states[th2 as usize][i];
        if state == end_state{
            (state2, i2) = states[th2 as usize][i-1];
            break;
        }
    }          
    
    if i1 > i2{
        (i1, i2) = (i2, i1);
        (state1, state2) = (state2, state1);
    }
    let d = i2 - i1;

    for _ in 0..d{
        state1 = hash(&state1, m_bits); 
        state1.push(0);   
    }

    loop{
        let h1 = hash(&state1, m_bits);
        let h2 = hash(&state2, m_bits);

        if h1 == h2{
            break;
        }

        state1 = h1;
        state2 = h2;
        state1.push(0);
        state2.push(0);
    }
    (state1, state2)
}
