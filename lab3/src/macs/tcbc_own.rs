use aes::Aes128;
use aes::cipher::{ BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, 
    generic_array::{GenericArray, typenum::U16},
};


type Block = U16;
const BlockSize: usize = 16;
const TruncSize: usize = 8;

pub struct TCBC{
    pub key:        Option<Vec<u8>>,
    pub prevstate:  Option<Vec<u8>>,
    pub curstate:   Option<Vec<u8>>,
    pub update: bool
}

fn aes_block_encrypt(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8>{
    if data.len() != BlockSize{
        panic!("Incorrect block length");
    }
    if key.len() != BlockSize{
        panic!("Incorrect key length");
    }

    let key = GenericArray::<u8, Block>::clone_from_slice(key);
    let mut data = GenericArray::<u8, Block>::clone_from_slice(data);
    
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut data);
    Vec::from(&data[..])
}

impl TCBC{
    pub fn SetKey(&mut self, key: Vec<u8>){
        if key.len() != BlockSize{
            panic!("Incorrect Key Length: {}", key.len());
        }
        self.key = Some(key);
        self.prevstate = Some(vec![0u8; BlockSize]);
        self.curstate = Some(vec![]);
    }

    pub fn MacAddBlock(&mut self, dataBlock: &Vec<u8>){
        if !self.update{
            panic!("Can't update state, digest is already calculated");
        }

        if dataBlock.len() == 0{
            return
        }

        let mut curstate = match &self.curstate{
            Some(p) => p.to_vec(),
            None => panic!("No cur state found")
        };

        if curstate.len() + dataBlock.len() >= BlockSize{
            let mut rem = (curstate.len() + dataBlock.len()) % BlockSize;

            curstate.append(&mut Vec::from(&dataBlock[0..dataBlock.len()-rem]));
            self.curstate = Some(Vec::from(&dataBlock[dataBlock.len()-rem..]));

            let mut prevstate = match &self.prevstate{
                Some(p) => p.to_vec(),
                None => panic!("No prev state found")
            };
            let mut key = match &self.key{
                Some(p) => p,
                None => panic!("No key found")
            };
 
            for i in 0..curstate.len()/BlockSize{
                for j in 0..BlockSize{
                    prevstate[j] ^= curstate[i * BlockSize + j];
                }
                prevstate = aes_block_encrypt(&key, &prevstate);
            }
            self.prevstate = Some(prevstate.to_vec());
        }
        else{
            for i in 0..dataBlock.len(){
                curstate.push(dataBlock[i]);
            }
            self.curstate = Some(curstate.to_vec());
        }
    }

    pub fn MacFinalize(&mut self) -> Vec<u8>{
        if !self.update{
            panic!("Can't update state, digest is already calculated");
        }
        let mut data = match &self.curstate{
            Some(d) => d.to_vec(),
            None => panic!("No current state found")
        };
        let mut prevstate = match &self.prevstate{
            Some(d) => d.to_vec(),
            None => panic!("No previous state found")
        };

        let mut padded_data = data;
        let rem = BlockSize - (padded_data.len() % BlockSize);
        for _ in 0..rem{
            padded_data.push(rem as u8);
        }

        self.curstate = Some(vec![]);
        self.MacAddBlock(&padded_data);

        let mac = match &self.prevstate{
            Some(p) => p.to_vec(),
            None => panic!("No prev state found")
        };
        self.update = false;
        Vec::from(&mac[..TruncSize])
    }

    pub fn ComputeMac(&mut self, data: &Vec<u8>) -> Vec<u8>{
        self.MacAddBlock(&data);
        self.MacFinalize()          
    }

    pub fn VerifyMac(&mut self, data: &Vec<u8>, tag: &Vec<u8>) -> bool{
        self.update = true;
        self.prevstate = Some(vec![0u8; BlockSize]);
        self.curstate = Some(vec![]);
        self.ComputeMac(&data) == *tag
    }

    pub fn digest(self) -> Vec<u8>{
        if self.update{
            panic!("No digest yet");
        }
        match &self.prevstate{
            Some(st) => st.to_vec(),
            None => panic!("No state found")
        }
    }
}
