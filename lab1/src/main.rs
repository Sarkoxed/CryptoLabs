use aes::Aes128;
use aes::cipher::{ 
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{GenericArray, typenum::U16}
};
use urandom;

#[derive(Debug)] 
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
    fn SetKey(&mut self, key: &[u8; 16]){
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
        let mut pad: u8 = 16 - (data.len() % 16) as u8;

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
                        println!("{}", data.len());
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
                            let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(data);
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

        let block_len = padded_data.len() / 16;
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
}

fn main() {
    let mut c = Cipher{
        bc: None,
        key: None,
        mode: None,
        IV: None,
        prev: None,
    };

    let key: [u8; 16] = [7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8];
    let iv: [u8; 16] = [7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8];

    c.SetKey(&key);
    c.SetMode("CBC");

    let pt = "Ya sobaka ti sobaka".as_bytes();

    for i in pt{
        print!("{}, ", i);
    }

    let ct = c.Encrypt(&pt, &iv, "PKCS7"); 
    for c in ct{
        print!("{}, ", c);
    }
}
