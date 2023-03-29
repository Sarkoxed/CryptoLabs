use aes::Aes128;
use aes::cipher::{ BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, 
    generic_array::{GenericArray, typenum::U16},
};

type Block = U16;
const BlockSize: usize = 16;

pub struct OMAC{
    bc:     Option<Aes128>,
    key:    Option<GenericArray<u8, Block>>,
    K1:     Option<GemericArray<u8, Block>>,
    K2:     Option<GemericArray<u8, Block>>,
    mac:   Option<GenericArray<u8, Block>>,
}

fn aes_block_encrypt(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8>{
    if data.len() != 16{
        panic!("Incorrect block length");
    }
    if key.len() != 16{
        panic!("Incorrect key length");
    }

    let key = GenericArray::<u8, Block>::clone_from_slice(key);
    let mut data = GenericArray::<u8, Block>::clone_from_slice(data);
    
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut data);
    Vec::from(&data[..])
}

impl OMAC{
    fn SetKey(&mut self, key: &[u8]){
        if key.len() != BlockSize{
            panic!("Incorrect Key Length: {}", key.len());
        }
        let key = GenericArray::<u8, Block>::clone_from_slice(key);
        let cipher = Aes128::new(&key);
        self.key = Some(key);
        self.bc = Some(cipher);
    }

    fn MacAddBlock(&mut self, dataBlock: &[u8]){
        
    }

    fn MacFinalize(self) -> Vec<u8>{
        match self.mac{
            Some(x) => Vec::from(x),
            None => panic!("No code found")
        }
    }

    fn ComputeMac(&mut self, data: &[u8]) -> Vec<u8>{

    }

    fn VerifyMac(self, data: &[u8], tag: &[u8]) -> bool{

    }
    

    




}
