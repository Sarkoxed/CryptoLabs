use aes::Aes128;
use aes::cipher::{ BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, 
    generic_array::{GenericArray, typenum::U16},
};

type Block = U16;
const BlockSize: usize = 16;

pub struct OMAC{
    pub key:        Option<Vec<u8>>,
    pub K1:         Option<Vec<u8>>,
    pub K2:         Option<Vec<u8>>,
    pub prevstate:  Option<Vec<u8>>,
    pub curstate:   Option<Vec<u8>>,
    pub update:     bool,
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

impl OMAC{
    pub fn SetKey(&mut self, key: Vec<u8>){
        if key.len() != BlockSize{
            panic!("Incorrect Key Length: {}", key.len());
        }
        self.key = Some(key);
        self.Derive();
        self.prevstate = Some(vec![0u8; BlockSize]);
        self.curstate = Some(vec![]);
    }

    fn Derive(&mut self){
        let key = match &self.key{
            Some(k) => k,
            None => panic!("No key found")
        };

        let k0 = aes_block_encrypt(&key, &vec![0u8; BlockSize]);  
        let mut carry1 = 0;
        let mut carry2 = 0;
        let mut k1 = vec![0u8; BlockSize];
        let mut k2 = vec![0u8; BlockSize];
        
        for i in (0..BlockSize).rev(){
            k1[i] = (k0[i] << 1) ^ carry1;
            carry1 = (k0[i] & 0x80) >> 7;
        }
        if carry1 == 1{
            k1[BlockSize - 1] ^= 0x87;
        }

        for i in (0..BlockSize).rev(){
            k2[i] = (k1[i] << 1) ^ carry2;
            carry2 = (k1[i] & 0x80) >> 7;
        }
        if carry2 == 1{
            k2[BlockSize - 1] ^= 0x87;
        }
        self.K1 = Some(k1);
        self.K2 = Some(k2);
    }

    pub fn MacAddBlock(&mut self, dataBlock: &Vec<u8>){
        if !self.update{
            panic!("Can't update the state, digest is alredy calculated");
        }
        if dataBlock.len() == 0{
            panic!("Incorrect block length");
        }

        let mut curstate = match &self.curstate{
            Some(p) => p.to_vec(),
            None => panic!("No cur state found")
        };

        if curstate.len() + dataBlock.len() > BlockSize{
            let mut rem = (curstate.len() + dataBlock.len()) % BlockSize;
            if rem == 0{
                rem = BlockSize;
            }

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

        if data.len() == 0{
            panic!("Incorrect final block size");
        }
        
        if data.len() == BlockSize{
            let round_key = match &self.K1{
                Some(k) => k,
                None => panic!("No k1 found")
            };
            for i in 0..BlockSize{
                data[i] ^= round_key[i];
            }
            data.append(&mut vec![0u8; BlockSize]);
            self.curstate = Some(vec![]);
            self.MacAddBlock(&data);            
        }
        else{
            let mut padded_data = data;
            let rem = padded_data.len() % BlockSize;
            
            padded_data.push(0x80); 
            for _ in 1..BlockSize - rem{
                padded_data.push(0);
            }

            let round_key = match &self.K2{
                Some(k) => k,
                None => panic!("No k2 found")
            };

            for i in 0..BlockSize{
                padded_data[i] ^= round_key[i];
            }
            padded_data.append(&mut vec![0u8; BlockSize]);
            self.curstate = Some(vec![]);
            self.MacAddBlock(&padded_data);
        }

        let mac = match &self.prevstate{
            Some(p) => p,
            None => panic!("No prev state found")
        };
        self.update = false;
        mac.to_vec()
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
