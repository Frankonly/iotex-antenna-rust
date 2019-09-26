pub mod constants;
pub mod hash;

use rand::rngs::OsRng;
use secp256k1::{key, Secp256k1};
use std::fmt;

pub struct Private_key(key::SecretKey);

impl fmt::Display for Private_key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

pub struct Public_key(key::PublicKey);

impl fmt::Display for Public_key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl Private_key {
    pub fn public_key(&self) -> Public_key {
        let secp = Secp256k1::signing_only();
        Public_key(key::PublicKey::from_secret_key(&secp, &self.0))
    }

    // pub fn sign(&self,hash: &hash::Hash256b) -> Signature {
    //     let secp = Secp256k1::signing_only();
    //     let hash = &secp256k1::Message::from_slice(&hash.0).expect("invalid 256 bits hash");
    //     let sig = secp.sign(hash, &self.0);
    //     sig.serialize_der(secp)
    // }
}

pub fn generate_key() -> Private_key {
    let mut rng = OsRng::new().expect("filed to get OsRng");
    Private_key(key::SecretKey::new(&mut rng))
}
mod tests {
    use super::*;
    #[test]
    fn test_generate_keys() {
        let x = generate_key();
        let y = generate_key();
        assert!(x.0 != y.0);
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (private_key, public_key) = secp.generate_keypair(&mut rng);
        let pri_key = Private_key(private_key);
        let pub_key = Public_key(public_key);
        assert_eq!(pri_key.public_key().0, pub_key.0);
    }
}
