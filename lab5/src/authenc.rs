use hmac::Hmac;
use sha2::Sha256;
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{GenericArray, typenum::U16},
};

const BlockSize: usize = 16;
const HmacSize: usize = 32;

enum Mode{
    Enc,
    Dec,
}

pub struct AuthenticEncryptor{
    mode:       Mode,
    aes_key:    Option<Vec<u8>>,
    hmac_key:   Option<Vec<u8>>,
    counter:         Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
    mac:        Option<Vec<u8>>,

    hmac:       Hmac::<Sha256>,
    cipher:     Option<Aes128>,
    enc_state:   Option<Vec<u8>>,
}

impl AuthenticEncryptor{
    pub fn SetKey(&mut self, key: Vec<u8>){
        if key.len() != BlockSize * 2{
            panic!("Incorrect Key Length: {}", key.len());
        }
 
        let k = &key[BlockSize..];
       
        let mut IV = Vec::from(&key[..BlockSize]);
        self.aes_key = Some(Vec::from(k));
        self.counter = Some(Vec::from(IV));
        let cip = Aes128::new(GenericArray::from_slice(k));
        self.cipher = Some(cip);
        self.hmac.update(&IV);
    }        
    
    fn update_counter(mut self){
        let mut counter: Vec<u8> = self.counter.expect("No counter found");      
        let carry: u8 = 1;
        for i in 0..BlockSize{
            if counter[BlockSize - i - 1] == 0xff && carry == 1{
                counter[BlockSize - i - 1] = 0;
                carry = 1;
            }
        }

    }

    fn ctr(&mut self, dataBlock: &Vec<u8>) -> Vec<u8>{
                
    }

    pub fn AddBlock(&mut self, dataBlock: &Vec<u8>, isFinal: bool) -> Vec<u8>{
        let mut block: Vec<u8>;
        let mut mac: Vec<u8>;

        match self.mode{
            Mode::Dec => {
                
            }
            Mode::Enc => {

            }
        }
    }

    pub fn ProcessData(data: &Vec<u8>) -> Vec<u8>{
        
    }
}
