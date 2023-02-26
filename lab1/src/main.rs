use aes::Aes128;
use aes::cipher::{ 
//    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, 
    generic_array::{GenericArray, typenum::U8} // ArrayLength
};

#[derive(Debug)] 
enum CipherMode{
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
}

struct Cipher{
    bc:    Option<Aes128>,
    key:   Option<GenericArray<u8, U8>>,
    mode:  Option<CipherMode>,
    IV:    Option<GenericArray<u8, U8>>,
    nonce: Option<GenericArray<u8, U8>>,
}

impl Cipher{
    fn SetKey(&mut self, key: &[u8]){
        if key.len() != 16{
            panic!("Key length must be 16");
        }
        
//        let tmp = GenericArray::clone_from_slice(key);
//        self.key = Some(tmp);

        if let Some(key) = self.key{
            for i in 0..16{
                println!("{}", key[i]);
            }
        }
//        self.bc = Aes128::new(&self.key);
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
        let mut res = Vec::from(data);
        for _ in 0..pad{
            res.push(pad);
        }
        res
    }

    fn ProcessBlockEncrypt(&self, data: &[u8], isFinalBlock: bool, padding: &str){
        let mut block: &[u8];
        match padding{
            "PKCS7" => block = &self.pad(data)[..],
            "NON" => block = data,
            _ => panic!("Unknown padding scheme"),
        };
    }

    fn BlockCipherEncrypt(&self, data: &[u8]){
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

    let key = [7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8, 7, 8];
    let t = GenericArray::clone_from_slice(key);
    //c.SetKey(&key);
    //c.SetMode("ECB");
    //
    //match c.mode{
    //    Some(mode) => println!("{:?}", mode),
    //    None => (),
    //}
}
