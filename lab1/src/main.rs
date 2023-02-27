use aes::Aes128;
use aes::cipher::{ 
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{GenericArray, typenum::U16},
};
use urandom;
use std::io;
use hex_literal::hex;

enum CipherMode{
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
}

struct Cipher{
    bc:     Option<Aes128>,
    key:    Option<GenericArray<u8, U16>>,
    mode:   Option<CipherMode>,
    IV:     Option<GenericArray<u8, U16>>,
    prev:   Option<GenericArray<u8, U16>>,
}

impl Cipher{
    fn SetKey(&mut self, key: &[u8]){
        if key.len() != 16{
            panic!("Incorrect key length");
        }
        let key = GenericArray::<u8, U16>::clone_from_slice(key);
        let cipher = Aes128::new(&key);
        self.key = Some(key);
        self.bc = Some(cipher);
    }

    fn SetMode(&mut self, mode: &str){
        match mode{
            "ECB" => self.mode = Some(CipherMode::ECB),
            "CBC" => self.mode = Some(CipherMode::CBC),
            "CFB" => self.mode = Some(CipherMode::CFB),
            "OFB" => self.mode = Some(CipherMode::OFB),
            "CTR" => self.mode = Some(CipherMode::CTR),
            _ => panic!("Unknown mode")
        }
    }

    fn pad(&self, data: &[u8]) -> Vec<u8>{
        let pad: u8 = 16 - (data.len() % 16) as u8;

        let mut res: Vec<u8> = Vec::from(data.clone());
        for _ in 0..pad{
            res.push(pad);
        }
        res
    }

    fn genIV(&mut self, len: usize){        
        let mut iv = [0u8; 16];
        let mut rng = urandom::new();
    
        for i in 0..len{
            iv[i] = rng.next::<u8>();
        }
        let iv = GenericArray::<u8, U16>::clone_from_slice(&iv);
        self.IV = Some(iv);
        self.prev = Some(iv);
    }


    fn ProcessBlockEncrypt(&mut self, data: &mut [u8]) -> Vec<u8>{
        match &self.mode{
            Some(mode) => {
                match mode{
                    CipherMode::ECB => {
                        let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(data);
                        self.BlockCipherEncrypt(&mut block);
                        Vec::from(block.as_slice())
                    }
                    CipherMode::CBC => {
                        match self.IV{
                            Some(_) => (),
                            None => self.genIV(16),
                        }

                        if let Some(prev) = self.prev{
                            let mut block = [0u8; 16];
                            for i in 0..16{
                                block[i] = data[i] ^ prev[i];
                            }

                            let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&block);
                            self.BlockCipherEncrypt(&mut block);
                            self.prev = Some(block);
                            Vec::from(block.as_slice())
                        }else{
                            panic!("Iv is None");
                        }
                    }
                    CipherMode::CFB => {
                        match self.IV{
                            Some(_) => (),
                            None => self.genIV(16),
                        }

                        if let Some(prev) = self.prev{
                            let mut block: GenericArray<u8, U16> = prev;
                            self.BlockCipherEncrypt(&mut block);
                            for i in 0..data.len(){
                                data[i] = block[i] ^ data[i];
                                block[i] = data[i];
                            }
                            
                            self.prev = Some(block);
                            Vec::from(data)
                        }else{
                            panic!("Prev is None");
                        }
                    }
                    CipherMode::OFB => {
                        match self.IV{
                            Some(_) => (),
                            None => self.genIV(16),
                        }
                        if let Some(prev) = self.prev{
                            let mut block: GenericArray<u8, U16> = prev;
                            self.BlockCipherEncrypt(&mut block);
                            
                            self.prev = Some(block);

                            for i in 0..data.len(){
                                data[i] = block[i] ^ data[i];
                            }
                            
                            Vec::from(data)
                        }else{
                            panic!("Prev is None");
                        }
                    }
                    CipherMode::CTR => {
                        match self.IV{
                            Some(_) => (),
                            None => self.genIV(12),
                        }
                        if let Some(prev) = self.prev{
                            let mut block: GenericArray<u8, U16> = prev;
                            self.BlockCipherEncrypt(&mut block);

                            let mut tmp: u32 = 0;
                            for i in 0..4{
                                tmp *= 256;
                                tmp += prev[12 + i] as u32;
                            }
                            tmp += 1;
                            if tmp == 1 << 32 - 1{
                                panic!("End of counter");
                            }
                            let mut new_prev = prev;
                            for i in 0..4{
                                new_prev[15 - i] = (tmp % 256) as u8;
                                tmp /= 256;
                            }
                            self.prev = Some(new_prev);

                            for i in 0..data.len(){
                                data[i] = block[i] ^ data[i];
                            }
                            
                            Vec::from(data)
                        }else{
                            panic!("Prev is None");
                        }
                    }
                }
            }
            None => panic!("Mode is not specified"),
        }
    }

    fn BlockCipherEncrypt(&self, data: &mut GenericArray<u8, U16>){
        if data.len() != 16{
            panic!("Incorrect block length");
        }

        match &self.bc{
            Some(cipher) => cipher.encrypt_block(data),
            None => panic!("Encryption of None"),
        }
    }

    fn Encrypt(&mut self, data: &[u8], iv: &[u8], padding: &str) -> Vec<u8>{
        match self.bc{
            Some(_) => (),
            None => panic!("Block Cipher is not initialized"),
        }

        if iv.len() != 0{
            self.IV = Some(GenericArray::<u8, U16>::clone_from_slice(iv));
            self.prev = self.IV;
        }

        let mut padded_data = match padding{
            "PKCS7" => self.pad(data),
            "NON" => Vec::from(data),
            _ => panic!("Unknown padding scheme"),
        };

        let block_len = (padded_data.len() + 15) / 16;
        let len = padded_data.len();

        let mut ciphertext: Vec<u8> = Vec::from([]);

        for i in 0..block_len - 1{
            let mut tmp: Vec<u8> = self.ProcessBlockEncrypt(&mut padded_data[16*i..16*(i + 1)]);
            ciphertext.append(&mut tmp);
        }
        let mut tmp: Vec<u8> = self.ProcessBlockEncrypt(&mut padded_data[(block_len - 1) * 16..len]);
        ciphertext.append(&mut tmp);
        ciphertext
    }

    fn ProcessBlockDecrypt(&mut self, data: &mut [u8]) -> Vec<u8>{
        match &self.mode{
            Some(mode) => {
                match mode{
                    CipherMode::ECB => {
                        let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(data);
                        self.BlockCipherDecrypt(&mut block);
                        Vec::from(block.as_slice())
                    }
                    CipherMode::CBC => {
                        if let Some(prev) = self.prev{
                            let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(data);
                            self.prev = Some(block);
                            self.BlockCipherDecrypt(&mut block);
                            for i in 0..16{
                                block[i] = block[i] ^ prev[i];
                            }
                            Vec::from(block.as_slice())
                        }else{
                            panic!("Iv is None");
                        }
                    }
                    CipherMode::CFB => {
                        if let Some(prev) = self.prev{
                            let mut block: GenericArray<u8, U16> = prev;
                            self.BlockCipherEncrypt(&mut block);
                            
                            if data.len() == 16{
                                let tmp = GenericArray::<u8, U16>::clone_from_slice(data);
                                self.prev = Some(tmp);
                            }

                            for i in 0..data.len(){
                                data[i] = block[i] ^ data[i];
                                block[i] = data[i];
                            }
                            Vec::from(data)
                        }else{
                            panic!("Prev is None");
                        }
                    }
                    CipherMode::OFB => {
                        self.ProcessBlockEncrypt(data)
                    }
                    CipherMode::CTR => {
                        self.ProcessBlockEncrypt(data)
                    }
                }
            }
            None => panic!("Mode is not specified"),
        }
    }

    fn BlockCipherDecrypt(&self, data: &mut GenericArray<u8, U16>){
        if data.len() != 16{
            panic!("Incorrect block length");
        }

        match &self.bc{
            Some(cipher) => cipher.decrypt_block(data),
            None => panic!("Encryption of None"),
        }
    }

    fn unpad(&self, data: &mut Vec<u8>){
        let it: usize = data[data.len()-1] as usize;
        for _ in 0..it{
            _ = data.pop();
        }
    }

    fn Decrypt(&mut self, data: &mut [u8], iv: &[u8], padding: &str) -> Vec<u8>{
        match self.bc{
            Some(_) => (),
            None => panic!("Block Cipher is not initialized"),
        }

        if iv.len() == 0{
            panic!("No IV provided");
        }else{
            self.IV = Some(GenericArray::<u8, U16>::clone_from_slice(iv));
            self.prev = self.IV;
        }

        let block_len = (data.len() + 15) / 16;
        let len = data.len();

        let mut plaintext: Vec<u8> = Vec::from([]);

        for i in 0..block_len - 1{
            let mut tmp: Vec<u8> = self.ProcessBlockDecrypt(&mut data[16*i..16*(i + 1)]);
            plaintext.append(&mut tmp);
        }
        let mut tmp: Vec<u8> = self.ProcessBlockDecrypt(&mut data[(block_len - 1) * 16..len]);
        plaintext.append(&mut tmp);

        match padding{
            "PKCS7" => self.unpad(&mut plaintext),
            "NON" => (),
            _ => panic!("Unknown padding scheme"),
        };
        plaintext
    }
}


fn randbytes(x: &mut [u8]){
    let mut rng = urandom::new();
    for i in 0..x.len(){
        x[i] = rng.next::<u8>();
    }
}

fn check_cbc(n: u16){
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    for _ in 0..n{
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        let mut pt = [0u8; 21];
        randbytes(&mut key);
        randbytes(&mut iv);
        randbytes(&mut pt);

        let pt1 = pt.clone();

        let mut c = Cipher{
            bc: None,
            key: None,
            mode: None,
            IV: None,
            prev: None,
        };
        c.SetKey(&key);
        c.SetMode("CBC");
        

        let ct = c.Encrypt(&mut pt, &iv, "PKCS7");

        let mut buf = [0u8; 32];
        let ct1 = Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(&pt1, &mut buf)
            .unwrap();
        assert_eq!(ct, ct1);
    }
}

fn decrypt_things(key: &[u8], cc: &[u8], mode: &str){
    let mut iv = cc.clone();
    iv = &iv[..16];
    

    let ct = cc.clone();
    let mut ct = Vec::from(&ct[16..]);

    let mut c = Cipher{
        bc: None,
        key: None,
        mode: None,
        IV: None,
        prev: None,
    };

    c.SetKey(&key);
    
    let pad = match mode{
        "CBC" => "PKCS7",
        "CTR" => "NON",
        _ => panic!("lol"),
    };
    c.SetMode(mode);

    let pt = c.Decrypt(&mut ct, &iv, pad);

    for i in pt{
        print!("{}", i as char);
    }
    println!();
}

fn print_hex(v: &[u8]){
    for i in v{
        print!("{:02x}", i);
    }
    println!();
}

fn check_encs(pt: &[u8]){
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    let mut nonce = [0u8; 16];
    randbytes(&mut key);
    randbytes(&mut iv);
    randbytes(&mut nonce);
    nonce[15] = 0;
    nonce[14] = 0;
    nonce[13] = 0;
    nonce[12] = 0;

    let mut c = Cipher{
        bc: None,
        key: None,
        mode: None,
        IV: None,
        prev: None,
    };

    println!();
    print_hex(&pt);
    println!();

    // ECB
    c.SetMode("ECB");
    c.SetKey(&key);
    let mut ct = c.Encrypt(&mut pt.clone(), &[], "PKCS7");
    print_hex(&ct);
    let pt1 = c.Decrypt(&mut ct, &iv, "PKCS7");
    print_hex(&pt1);
    assert_eq!(pt1, pt);
    println!();

    // CBC
    c.SetMode("CBC");
    c.SetKey(&key);
    let mut ct = c.Encrypt(&mut pt.clone(), &iv, "PKCS7");
    print_hex(&ct);
    let pt1 = c.Decrypt(&mut ct, &iv, "PKCS7");
    print_hex(&pt1);
    assert_eq!(pt1, pt);
    println!();

    // CFB
    c.SetMode("CFB");
    c.SetKey(&key);
    let mut ct = c.Encrypt(&mut pt.clone(), &iv, "PKCS7");
    print_hex(&ct);
    let pt1 = c.Decrypt(&mut ct, &iv, "PKCS7");
    print_hex(&pt1);
    assert_eq!(pt1, pt);
    println!();

    // OFB
    c.SetMode("OFB");
    c.SetKey(&key);
    let mut ct = c.Encrypt(&mut pt.clone(), &iv, "PKCS7");
    print_hex(&ct);
    let pt1 = c.Decrypt(&mut ct, &iv, "PKCS7");
    print_hex(&pt1);
    assert_eq!(pt1, pt);
    println!();

    // CTR
    c.SetMode("CTR");
    c.SetKey(&key);
    let mut ct = c.Encrypt(&mut pt.clone(), &nonce, "PKCS7");
    print_hex(&ct);
    let pt1 = c.Decrypt(&mut ct, &nonce, "PKCS7");
    print_hex(&pt1);
    assert_eq!(pt1, pt);
    println!();
}

    
fn main() {
    //let mut mode = String::new();
    //io::stdin().read_line(&mut mode).expect("Failed to read line");
    //let mode = mode.trim();

    //2
    check_cbc(10000);

    //2.5
    let key = hex!("140b41b22a29beb4061bda66b6747e14");
    let ct =  hex!("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");
    decrypt_things(&key, &ct, "CBC");
    let ct =  hex!("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253");
    decrypt_things(&key, &ct, "CBC");
    let key = hex!("36f18357be4dbd77f050515c73fcf9f2");
    let ct =  hex!("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329");
    decrypt_things(&key, &ct, "CTR");
    let ct =  hex!("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451");
    decrypt_things(&key, &ct, "CTR");

    //3
    let pt = *b"i hate rust i hate rust i hate rust i ha";
    check_encs(&pt);
}
