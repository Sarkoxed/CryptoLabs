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

    pub fn AddBlock(&mut self, dataBlock: Vec<u8>, isFinal: bool) -> Vec<u8>{
        let mut hmac = self.hmac.clone().expect("No initialized hmac found");

        let mut block;
        match self.mode{
            Mode::Enc => {
                block = dataBlock.clone();
                self.ctr(&mut block);
                
                hmac.update(&block.clone());
                if isFinal{
                    block.append(&mut hmac.clone().finalize().into_bytes().to_vec())
                }
                self.hmac = Some(hmac);
            }
            Mode::Dec => {
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

                if isFinal{
                    hmac.clone().verify_slice(&mac).unwrap();
                }
                self.hmac = Some(hmac);
            }
        }
        block
    }

    pub fn ProcessData(&mut self, data: &Vec<u8>) -> Vec<u8>{
        let mut res = vec![];
        let mut partres;

        match self.mode{
            Mode::Enc => {
                let mut nonce = self.nonce.clone().expect("No nonce found");
                res.append(&mut nonce);

                let blocklen = (data.len() + BlockSize - 1) / BlockSize;
                for i in 0..blocklen - 1{
                    partres = self.AddBlock(Vec::from(&data[i * BlockSize..(i + 1) * BlockSize]), false);
                    res.append(&mut partres);
                }
                partres = self.AddBlock(Vec::from(&data[(blocklen - 1) * BlockSize..]), true);
                res.append(&mut partres);
            }
            Mode::Dec => {
                let nonce = Vec::from(&data[..BlockSize]);
                self.SetNonce(nonce);
 
                if data.len() < BlockSize + HmacSize{
                    panic!("Wrong structure");
                }
                let blocklen = (data.len() - HmacSize - 1) / BlockSize;
                for i in 0..blocklen - 1{
                    partres = self.AddBlock(Vec::from(&data[(i + 1) * BlockSize..(i + 2) * BlockSize]), false);
                    res.append(&mut partres);
                }
                partres = self.AddBlock(Vec::from(&data[blocklen * BlockSize..]), true);
                res.append(&mut partres);
            }
        }
        res
    }
}
