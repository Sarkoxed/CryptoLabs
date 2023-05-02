use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::tools::{GenKey, GetShared};

pub struct Party{
    pub sk:        Scalar,
    pub pk:        MontgomeryPoint,
    pub sp:        MontgomeryPoint,
}

pub fn init_pary() -> Party{
    Party{
        sk: Scalar::from_bytes_mod_order_wide(&[0u8; 64]),
        pk: Identity::identity(),
        sp: Identity::identity(),
    }
}


fn sigma(){

}
