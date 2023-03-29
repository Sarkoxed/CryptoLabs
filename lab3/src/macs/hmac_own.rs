use sha2::{Sha256, Digest};

pub struct HMAC{
    pub key:        Option<Vec<u8>>,
    pub state:      Sha256,
    pub left:       Sha256,
    pub update: bool,
}

const BlockSize: usize = 64;
const ShaDigestSize: usize = 32;
const opad: u8 = 0x5c;
const ipad: u8 = 0x36;


impl HMAC{
    pub fn SetKey(&mut self, key: Vec<u8>){
        if key.len() == 0{
            panic!("Incorrect Key Length: {}", key.len());
        }
        let mut keyk;
        if key.len() > BlockSize{
            let mut hasher = Sha256::new();
            hasher.update(&key);
            keyk = Vec::from(&hasher.finalize()[..]);
        }
        else{
            keyk = key.clone();
        }

        for _ in keyk.len()..BlockSize{
            keyk.push(0);
        }
 
        self.key = Some(keyk.clone());
        let mut tmp1 = keyk.clone();
        let mut tmp2 = keyk;
        for i in 0..BlockSize{
            tmp1[i] ^= opad;
            tmp2[i] ^= ipad;
        }
        self.left.update(tmp1);

        self.state.update(tmp2);
    }

    pub fn MacAddBlock(&mut self, dataBlock: &Vec<u8>){
        if !self.update{
            panic!("Digest is already calculated");
        }
        self.state.update(dataBlock)
    }

    pub fn MacFinalize(&mut self) -> Vec<u8>{
        if !self.update{
            panic!("Digest is already calculated");
        }
        self.update = false; 
        self.left.update(&self.state.clone().finalize()[..]);
        Vec::from(&self.left.clone().finalize()[..])
    }

    pub fn ComputeMac(&mut self, data: &Vec<u8>) -> Vec<u8>{
        self.MacAddBlock(&data);
        self.MacFinalize()    
    }

    pub fn VerifyMac(&mut self, data: &Vec<u8>, tag: &Vec<u8>) -> bool{
        let key = match &self.key{
            Some(k) => k.to_vec(),
            None => panic!("No key found")
        };
        self.update = true;
        let mut tmp1 = key.clone();
        let mut tmp2 = key.clone();
        for i in 0..BlockSize{
            tmp1[i] ^= opad;
            tmp2[i] ^= ipad;
        }
        self.left = Sha256::new();
        self.left.update(tmp1);

        self.state = Sha256::new();
        self.state.update(tmp2);
        self.ComputeMac(&data) == *tag
    }

    pub fn digest(self) -> Vec<u8>{
        if self.update{
            panic!("No digest yet");
        }
        Vec::from(&self.left.finalize()[..])
    }

    pub fn reset(&mut self){
        let key = match &self.key{
            Some(k) => k.to_vec(),
            None => panic!("No key found"),
        };
        self.SetKey(key);
        self.update = true;
    }
}


