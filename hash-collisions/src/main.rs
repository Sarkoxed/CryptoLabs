use sha256::{digest, try_digest};
use std::collections::HashMap;
use urandom;
use hex;
use std::io;

fn randbytes(x: &mut [u8]){
    let mut rng = urandom::new();
    for i in 0..x.len(){
        x[i] = rng.next::<u8>();
    }
}

fn to_binary(c: char) -> String{
    match c {
        '0' => String::from("0000"),
        '1' => String::from("0001"),
        '2' => String::from("0010"),
        '3' => String::from("0011"),
        '4' => String::from("0100"),
        '5' => String::from("0101"),
        '6' => String::from("0110"),
        '7' => String::from("0111"),
        '8' => String::from("1000"),
        '9' => String::from("1001"),
        'a' => String::from("1010"),
        'b' => String::from("1011"),
        'c' => String::from("1100"),
        'd' => String::from("1101"),
        'e' => String::from("1110"),
        'f' => String::from("1111"),
        _ => String::from(""),
    }
}

fn bin(h: String, m: u8) -> String{
    if ((m + 3) / 4) > h.len() as u8{
        panic!("Wrong number of bits");
    }

    let m_t= (m + 3)/ 4;

    let mut res = String::new();
    let beg = h.len() - m_t as usize;

    for c in &h.as_bytes()[beg..]{
        let kek = to_binary(*c as char);
        res = res + &kek;
    }
    String::from(&res[res.len() - m as usize..])
}


fn birthday_sha256(m: u8) -> (String, String){
    let mut S = HashMap::<String, [u8; 16]>::new();
    loop {
        let mut x = [0u8; 16];
        randbytes(&mut x);
        let H = bin(digest(&x), m);

        let tmp = S.get(&H);
        _ = match tmp{
            Some(coll) => return (hex::encode(*coll), hex::encode(x)),
            None => S.insert(H, x),
        }
    }
}    

fn pollard(){}

fn main(){
    //let mut index = String::new();
    //io::stdin().read_line(&mut index).expect("Failed to read line");
    //let index: u8 = index.trim().parse().expect("Index entered was not a num");
    // 
    //let (x, y) = birthday_sha256(index);
    //println!("{}", x);
    //println!("{}", y);
}
