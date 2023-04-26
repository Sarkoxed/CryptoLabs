use hmac::Hmac;
use sha2::Sha256;
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{GenericArray, typenum::U16},
};

use rand::RngCore;
//use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

type Block = U16;
const BlockSize: usize = 16;
const HmacSize: usize = 32;

enum Mode{
    Enc,
    Dec,
}

pub struct AuthenticEncryptor{
    mode:       Mode,
    counter:    Option<Vec<u8>>,

    hmac:       Option<Hmac::<Sha256>>,
    cipher:     Option<Aes128>,

    enc_state:  Option<Vec<u8>>,
    
    nonce:      Option<Vec<u8>>,
    result:     Option<Vec<u8>>,
    mac:        Option<Vec<u8>>,
}

fn rand_bytes(n: usize) -> Vec<u8>{
    let rand = ChaCha20Rng::from_entropy();
    let mut res = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut res);
    res
}

impl AuthenticEncryptor{
    pub fn SetKey(&mut self, key: Vec<u8>){
        if key.len() != BlockSize * 2{
            panic!("Incorrect Key Length: {}", key.len());
        }
 
        let aes_key = &key[BlockSize..];
        let hmac_key = &key[..BlockSize];
       
        let cip = Aes128::new(GenericArray::from_slice(aes_key));
        self.cipher = Some(cip);
        self.result = Some(vec![]);

        let mut hmac = Hmac::<Sha256>::new_from_slice(&key[..]).unwrap();
        self.hmac = Some(hmac);

        match self.mode{
            Mode::Enc => {
                let mut nonce = rand_bytes(BlockSize);
                nonce[0] = 0;
        
                self.counter = Some(Vec::from(nonce));
                self.nonce = Some(Vec::from(nonce));

                self.SetNonce(nonce);            
            }
            _ => ()
        }
    }

    fn SetNonce(&mut self, nonce: Vec<u8>){
        match self.nonce{
            None => (),
            Some(_) => panic!("Nonce already exists")
        }

        let mut hmac = self.hmac.expect("No initialized hmac found");
        hmac.update(&nonce);
        self.counter = Some(nonce);
        self.nonce = Some(nonce);
    }

    fn update_counter(&mut self) -> Vec<u8>{
        let mut counter: Vec<u8> = self.counter.expect("No counter found");
        let carry: u8 = 1;
        for i in 0..BlockSize{
            if counter[BlockSize - i - 1] == 0xff && carry == 1{
                counter[BlockSize - i - 1] = 0;
                carry = 1;
            }
            else{
                counter[BlockSize - i - 1] += 1;
                carry = 0;
                break;
            }
        }

        if carry == 1{
            panic!("The counter needs to be reset");
        }
        
        let cip = self.cipher.expect("No cipher found");
        let mut data = GenericArray::<u8, Block>::clone_from_slice(&counter[..]);
 
        cip.encrypt_block(&data);
        self.counter = Some(counter);
        Vec::from(&data[..])
    }


    fn ctr(&mut self, dataBlock: &Vec<u8>){
        let mut enc_state = self.enc_state.expect("No state found");
        for i in 0..dataBlock.len(){
            if enc_state.len() == 0{
                enc_state = self.update_counter();
            }
            let tmp = enc_state[0];
            enc_state.remove(0);
            dataBlock[i] ^= tmp;
        }
        self.enc_state = Some(enc_state);
    }

    pub fn AddBlock(&mut self, dataBlock: &Vec<u8>, isFinal: bool){
        let mut block: Vec<u8>;
        let mut mac: Vec<u8>;
        
        let mut hmac = self.hmac.expect("No initialized hmac found");

        match self.mode{
            Mode::Enc => {
                self.ctr(dataBlock);
                let mut ct: Vec<u8> = self.result.expect("No ciphertext found");
                ct.append(&mut dataBlock);
                self.result = Some(ct);
                
                hmac.update(dataBlock.clone());
                if isFinal{
                    self.mac = Some(hmac.finalize());
                }
            }
            Mode::Dec => {
                if isFinal{
                    if dataBlock.len() < HmacSize{
                        panic!("No mac found in block");
                    }
                    let mac = &dataBlock[dataBlock.len()-HmacSize..];
                    dataBlock = &Vec::from(&dataBlock[..dataBlock.len() - HmacSize]);
                }
                hmac.update(dataBlock.clone());
                self.ctr(dataBlock);

                let mut pt: Vec<u8> = self.result.expect("No plaintext found");
                pt.append(&mut dataBlock);
                self.result = Some(pt);

                if isFinal{
                    hmac.verify_slice(mac).unwrap();
                }
            }
            other => panic!("Not an option")
        }
    }

    pub fn ProcessData(&mut self, data: &Vec<u8>) -> Vec<u8>{
        let mut res = vec![];
        match self.mode{
            Mode::Enc => {
                self.AddBlock(data, true);
                let mut nonce = self.nonce.expect("No nonce found");
                let mut ciphertext = self.result.expect("No ct found");
                let mut mac = self.mac.expect("No mac found");
                res.append(&mut nonce);
                res.append(&mut ciphertext);
                res.append(&mut mac);
            }
            Mode::Dec => {
                let nonce = &data[..BlockSize];
                self.AddBlock(&Vec::from(&data[BlockSize..]), true);
                let mut plaintext = self.result.expect("No pt found");
            }
            other => panic!("Not an option!")
        }
        res
    }
}
