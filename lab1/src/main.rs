use aes::Aes128;
use aes::cipher::{ 
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
    prev_c: Option<GenericArray<u8, U16>>,
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
        let mut pad: u8 = (data.len() % 16).try_into().unwrap();
        if pad == 0{
            pad = 16;
        }
        let mut res: Vec<u8> = Vec::from(data);
        for _ in 0..pad{
            res.push(pad);
        }
        res
    }

    fn ProcessBlockEncrypt(&self, data: &[u8], isFirstBlock: bool) -> Vec<u8>{
        match self.mode{
            Some(mode) => {
                match mode{
                    ECB => {
                        let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(data);
                        self.BlockCipherEncrypt(&mut block);
                        Vec::from(block.as_slice());
                    },
                    CBC => {
                        if isFirstBlock{
                            let mut rng = urandom::new();
                            let mut iv = [0u8; 16];

                            for i in 0..16{
                                iv[i] = rng.next::<u8>();
                            }
                        }
                    }                            
                }
            },
            None => panic!("Mode is not specified"),
        }
    }

    fn BlockCipherEncrypt(&self, data: &mut GenericArray<u8, U16>){
        if data.len() != 16{
            panic!("Incorrect block length");
        }

        match self.bc{
            Some(cipher) => cipher.encrypt_block(&mut data),
            None => panic!("Encryption of None"),
        }
    }

    fn Encrypt(&self, data: &[u8], iv: &[u8], padding: &str) -> Vec<u8>{
        match self.bc{
            Some(_) => (),
            None => panic!("Block Cipher is not initialized"),
        }

        let mut padded_data = match padding{
            "PKCS7" => &self.pad(data)[..],
            "NON" => data.clone(),
            _ => panic!("Unknown padding scheme"),
        };

        let block_len = padded_data.len() / 16;
        for i in 0..block_len - 1{
            self.ProcessBlockEncrypt(&padded_data[16*i..17*i]);
        }
        self.ProcessBlockEncrypt(&padded_data[(block_len - 1) * 16..padded_data.len()]);
        Vec::from(padded_data);
    }
}

fn main() {
    let mut c = Cipher{
        bc: None,
        key: None,
        mode: None,
        IV: None,
        nonce: None,
    };

    let key: [u8; 16] = [7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8];
    c.SetKey(&key);
    //c.SetMode("ECB");
    //
    //match c.mode{
    //    Some(mode) => println!("{:?}", mode),
    //    None => (),
    //}
}
