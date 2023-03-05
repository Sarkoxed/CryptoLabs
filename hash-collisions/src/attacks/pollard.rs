use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc;
use std::collections::HashMap;

use std::time::Duration;

use crate::tools::{new_hash, hash, randbytes, hsb, lsb};

fn dist_point(h: &Vec<u8>, q: usize) -> bool{
    if q == 0{
        return true
    }
    let h = hsb(&h, q);
    for i in h{
        if i != 0{
            return false
        }
    }
    true
}

pub fn pollard_short(n_threads: u8, m_bits: usize) -> (Vec<u8>, Vec<u8>){ // , k_bits: usize
    if n_threads <= 1{
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, (u32, u8)>::new()));
    let q = m_bits as i32 / 2 - (n_threads as f64).log2().floor() as i32;
    let q = if q > 0 {q as usize} else {0 as usize};

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    let mut inits = vec![];
    for th in 0..n_threads{
        let pairs_f = Arc::clone(&pairs);
        let txi = tx.clone();

        let mut state = [0u8; 16];
        randbytes(&mut state);
        let mut state = Vec::from(state);
        inits.push(state.clone());

        let handle = thread::spawn(move || {
            state.push(0);
            let mut counter: u32 = 1;
            loop{
                println!("Thread {}: state = {}, q = {}", th, hex::encode(&state), q);
                let mut h = new_hash(&state, m_bits); 
                h.push(0);
                if dist_point(&h, q){
                    println!("I am dist point: {:?}, {}, {}, {:?}", &h, counter, th, hex::encode(state));
                    let mut map = match pairs_f.lock(){
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };
                    println!("Unlocked {}", th);
                    
                    let tmp = (*map).get(&vec![]);
                    if let Some(_prev) = tmp{       // well to stop we have to wait until the dist
                                                    // point
                        break;
                    }
                    println!("Passed {}", th);

                    let tmp = (*map).get(&h);
                    if let Some(prev) = tmp{
                        println!("found, {}", th);
                        let (c2, th2) = prev;
                        let c2 = *c2;
                        let th2 = *th2;
                        (*map).insert(vec![], (0, 0));
                        _ = txi.send((th, counter, th2, c2));
                        break;
                    }else{
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

    let (mut th1, mut i1, mut th2, mut i2) = match rx.recv(){
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };
    
    println!("ending all the threads");
    for (i, handle) in handles.into_iter().enumerate(){
        println!("{i}");
        handle.join().unwrap();
    }

    if i1 > i2{
        (i1, i2) = (i2, i1);
        (th1, th2) = (th2, th1);
    }

    let d = i2 - i1;
    
    println!("thread is {}, {}", th1, inits.len());
    let mut state1 = (&inits[th1 as usize]).clone();
    let mut state2 = (&inits[th2 as usize]).clone();

    state1.push(0);
    state2.push(0);

    println!("Got: state1 = {}, i1 = {}, state2 = {}, i2 = {}, h1 = {}, h2 = {}", hex::encode(&state1), i1, hex::encode(&state2), i2, hex::encode(new_hash(&state1, m_bits)), hex::encode(new_hash(&state2, m_bits)));

//    let mut state1 = hex::decode("47828172365b028798a0adf7f7c4885a").unwrap();
//    let mut state2 = hex::decode("7d8cb1cf7ac16bb3cc4657d01b7dc09b").unwrap();
//    let mut i1 = 6;
//    let mut i2 = 19;
//    let mut d = i2 - i1;
 
    println!("Got: state1 = {}, i1 = {}, state2 = {}, i2 = {}, h1 = {}, h2 = {}", hex::encode(&state1), i1, hex::encode(&state2), i2, hex::encode(new_hash(&state1, m_bits)), hex::encode(new_hash(&state2, m_bits)));
    for _ in 0..d{
        state2 = new_hash(&state2, m_bits);
        state2.push(0);
    }

    loop{
        let h1 = new_hash(&state1, m_bits);
        let h2 = new_hash(&state2, m_bits);

        if h1 == h2{
            break;
        }

        state1 = h1;
        state2 = h2;
        state1.push(0);
        state2.push(0);
    }
        
    assert_eq!(new_hash(&state1, m_bits), new_hash(&state2, m_bits));
    println!("returning");
    (state1, state2)
}

pub fn pollard_full(n_threads: u8, m_bits: usize) -> (Vec<u8>, Vec<u8>){ // , k_bits: usize
    if n_threads <= 1{
        panic!("Not enough threads");
    }

    let pairs = Arc::new(Mutex::new(HashMap::<Vec<u8>, (u32, u8)>::new()));
    let q = m_bits as i32 / 2 - (n_threads as f64).log2().floor() as i32;
    let q = if q > 0 {q as usize} else {0 as usize};

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    let mut inits = vec![];
    for th in 0..n_threads{
        let pairs_f = Arc::clone(&pairs);
        let txi = tx.clone();

        let mut state = [0u8; 16];
        randbytes(&mut state);
        let mut state = Vec::from(state);
        inits.push(state.clone());

        let handle = thread::spawn(move || {
            state.push(0);
            let mut counter: u32 = 1;
            loop{
                println!("Thread {}: state = {}, q = {}", th, hex::encode(&state), q);
                let mut h = hash(&state); 
                let h_1 = lsb(&h, m_bits);
                h.push(0);
                if dist_point(&h, q){
                    println!("I am dist point: {:?}, {}, {}", &h, counter, th);
                    let mut map = match pairs_f.lock(){
                        Ok(val) => val,
                        Err(error) => panic!("{error}"),
                    };
                    println!("Unlocked {}", th);
                    
                    let tmp = (*map).get(&vec![]);
                    if let Some(_prev) = tmp{
                        break;
                    }
                    println!("Passed {}", th);

                    let tmp = (*map).get(&h_1);
                    if let Some(prev) = tmp{
                        println!("found, {}", th);
                        let (c2, th2) = prev;
                        let c2 = *c2;
                        let th2 = *th2;
                        (*map).insert(vec![], (0, 0));
                        _ = txi.send((th, counter, th2, c2));
                        break;
                    }else{
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

    let (mut th1, mut i1, mut th2, mut i2) = match rx.recv(){
        Ok(val) => val,
        Err(error) => panic!("{error}"),
    };
    
    println!("ending all the threads");
    for (i, handle) in handles.into_iter().enumerate(){
        println!("{i}");
        handle.join().unwrap();
    }

    if i1 > i2{
        (i1, i2) = (i2, i1);
        (th1, th2) = (th2, th1);
    }

    let d = i2 - i1;

    let mut state1 = (&inits[th1 as usize]).clone();
    let mut state2 = (&inits[th2 as usize]).clone();
    state1.push(0);
    state2.push(0);

    println!("Got: state1 = {}, i1 = {}, state2 = {}, i2 = {}, h1 = {}, h2 = {}", hex::encode(&state1), i1, hex::encode(&state2), i2, hex::encode(new_hash(&state1, m_bits)), hex::encode(new_hash(&state2, m_bits)));
    for _ in 0..d{
        state2 = hash(&state2);
        state2.push(0);
    }

    let mut count = 0;
    loop{
        let h1 = hash(&state1);
        let h2 = hash(&state2);

        if lsb(&h1, m_bits) == lsb(&h2, m_bits){
            break;
        }

        state1 = h1;
        state2 = h2;
        state1.push(0);
        state2.push(0);
        count += 1;
        if count > i1 || count > i2{
            break;
        }
    }
        
    assert_eq!(new_hash(&state1, m_bits), new_hash(&state2, m_bits));
    println!("returning");
    (state1, state2)
}
