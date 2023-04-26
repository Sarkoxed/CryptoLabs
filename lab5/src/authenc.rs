use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;

use sha2::Sha256;

use aes::Aes128;
use aes::cipher::BlockEncrypt;
use aes::cipher::{
    generic_array::{GenericArray, typenum::U16},
};

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

type Block = U16;
const BlockSize: usize = 16;
const HmacSize: usize = 32;

pub enum Mode{
    Enc,
    Dec,
}

pub struct AuthenticEncryptor{
    pub mode:       Mode,
    pub counter:    Option<Vec<u8>>,

    pub hmac:       Option<Hmac::<Sha256>>,
    pub cipher:     Option<Aes128>,

    pub enc_state:  Option<Vec<u8>>,

    pub nonce:      Option<Vec<u8>>,
    pub result:     Option<Vec<u8>>,
    pub mac:        Option<Vec<u8>>,
}

pub fn rand_bytes(n: usize) -> Vec<u8>{
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
 
        let aes_key = &key[..BlockSize];
        let hmac_key = &key[BlockSize..];
       
        let cip = Aes128::new(GenericArray::from_slice(aes_key));
        self.cipher = Some(cip);
        self.result = Some(vec![]);

        self.enc_state = Some(vec![]);

        let hmac = Mac::new_from_slice(hmac_key).unwrap();
        let hmac: Hmac::<Sha256> = hmac;
        self.hmac = Some(hmac);

        match self.mode{
            Mode::Enc => {
                let mut nonce = rand_bytes(BlockSize / 2);    
                for _ in 0..BlockSize/2{
                    nonce.push(0);
                }
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

        let mut hmac: Hmac<Sha256> = self.hmac.clone().expect("No initialized hmac found");
        hmac.update(&nonce);
        self.counter = Some(nonce.clone());
        self.nonce = Some(nonce.clone());
        self.hmac = Some(hmac);
    }

    fn update_counter(&mut self) -> Vec<u8>{
        let mut counter: Vec<u8> = self.counter.clone().expect("No counter found");

        let cip = self.cipher.clone().expect("No cipher found");
        let mut out = GenericArray::<u8, Block>::clone_from_slice(&counter[..]);
        cip.encrypt_block(&mut out);
 
        let mut carry: u8 = 1;
        for i in 0..BlockSize{
            if counter[BlockSize - i - 1] == 0xff && carry == 1{
                counter[BlockSize - i - 1] = 0;
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
        self.counter = Some(counter);

        Vec::from(&out[..])
    }


    fn ctr(&mut self, dataBlock: &mut Vec<u8>){
        let mut enc_state = self.enc_state.clone().expect("No state found");
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

    pub fn AddBlock(&mut self, dataBlock: &mut Vec<u8>, isFinal: bool){
        let mut hmac = self.hmac.clone().expect("No initialized hmac found");

        match self.mode{
            Mode::Enc => {
                self.ctr(dataBlock);
                let mut ct: Vec<u8> = self.result.clone().expect("No ciphertext found");
                ct.append(&mut dataBlock.clone());
                self.result = Some(ct);
                
                hmac.update(&dataBlock.clone());
                if isFinal{
                    self.mac = Some(hmac.clone().finalize().into_bytes().to_vec());
                }
                self.hmac = Some(hmac);
            }
            Mode::Dec => {
                let mut block;
                let mut mac = vec![];

                if isFinal{
                    if dataBlock.len() < HmacSize{
                        panic!("No mac found in block");
                    }
                    mac = Vec::from(&dataBlock[dataBlock.len()-HmacSize..]);
                    block = Vec::from(&dataBlock[..dataBlock.len() - HmacSize]);
                }
                else{
                    block = dataBlock.clone(); 
                }
                hmac.update(&block.clone());
                self.ctr(&mut block);

                let mut pt: Vec<u8> = self.result.clone().expect("No plaintext found");
                pt.append(&mut block.clone());
                self.result = Some(pt);

                if isFinal{
                    hmac.clone().verify_slice(&mac).unwrap();
                }
                self.hmac = Some(hmac);
            }
        }
    }

    pub fn ProcessData(&mut self, data: &Vec<u8>) -> Vec<u8>{
        let mut res = vec![];
        match self.mode{
            Mode::Enc => {
                self.AddBlock(&mut data.clone(), true);
                let mut nonce = self.nonce.clone().expect("No nonce found");
                let mut ciphertext = self.result.clone().expect("No ct found");
                let mut mac = self.mac.clone().expect("No mac found");
                res.append(&mut nonce);
                res.append(&mut ciphertext);
                res.append(&mut mac);
            }
            Mode::Dec => {
                let nonce = Vec::from(&data[..BlockSize]);
                self.SetNonce(nonce);
                self.AddBlock(&mut Vec::from(&data[BlockSize..]), true);
                res = self.result.clone().expect("No pt found");
            }
        }
        res
    }
}
